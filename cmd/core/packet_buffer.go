// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	cilium "github.com/cilium/ebpf"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/rs/zerolog/log"
)

// BufferingOptions bounds shared payload storage and each session's admission.
// These sizes are fixed for the lifetime of the reader and its kernel ring.
type BufferingOptions struct {
	Packets    uint32
	PerSession uint32
	FrameBytes uint32
	Retention  time.Duration
}

const noBufferedPacket = uint32(math.MaxUint32)

type packetBufferSender interface {
	Prepare() error
	Send(ebpf.RenderedBuffer) error
	Close() error
}

type bufferedPacket struct {
	record        ebpf.BufferRecord
	arrived       time.Time
	next          uint32
	owner         *bufferOwner
	cycle         *bufferCycle
	sent          bool
	discardReason string
}
type bufferCycle struct {
	farID                                                   uint32
	lane                                                    uint32
	cookie                                                  uint64
	head                                                    uint32
	received, completed                                     uint64
	canceled                                                bool
	draining, terminal                                      bool
	grace                                                   <-chan struct{}
	ready                                                   bool
	ioDone                                                  <-chan struct{}
	failedAt                                                time.Time
	drainStarted, drainReady, bufferedUntil, bufferedCutoff time.Time
	bufferedBAR, bufferedInfinite                           bool
}
type packetBufferSession struct {
	owner    *bufferOwner
	cycles   map[uint32]*bufferCycle
	revision uint64
}
type bufferOwner struct {
	discardExpiry, discardCancellation uint64
	noticeReady                        bool
	conn                               *PfcpConnection
	association                        *NodeAssociation
	session                            *Session
	cycles                             map[uint32]*bufferCycle
	nextCookie                         uint64
	active, canceled, graced, released bool
	terminal                           bool
	grace                              <-chan struct{}
	retirement                         *sessionRetirement
	resourcesDone                      <-chan struct{}
}

// PacketBuffering owns one application ring reader and one bounded payload pool
// shared by N4/Sxa/Sxb. Session queues and their records are owned by stateMu;
// mu protects only shared registry, admission reservations and free slot IDs.
type PacketBuffering struct {
	metricsMu                        sync.Mutex
	metricsRetained                  uint32
	metricsOverflow, metricsCanceled uint64
	// prepareMu serializes startup context ownership with cancellation.
	prepareMu                sync.Mutex
	prepareCancel            context.CancelFunc
	prepareOnce              sync.Once
	prepareCancelOnce        sync.Once
	prepareDone, prepareStop chan struct{}
	prepareError             error
	plane                    *ebpf.BpfObjects
	sender                   packetBufferSender
	complete                 func(ebpf.BufferCommand) (ebpf.BufferCommand, error)
	reader                   *ebpf.BufferReader
	options                  BufferingOptions
	mu                       sync.Mutex
	owners                   map[uint64]*bufferOwner
	work                     map[uint64]*bufferOwner
	reserved                 uint32
	storage                  []byte
	entries                  []bufferedPacket
	free                     []uint32
	closed                   bool
	stop                     chan struct{}
	progress                 chan struct{}
	failures                 chan error
	wg                       sync.WaitGroup
	closeOnce                sync.Once
	closeError               error
	baseTime                 time.Time
	baseNS                   uint64
}

// NewPacketBuffering preallocates payloads and starts the sole ring consumer.
// Session journals publish buffering lifetimes only after output preparation.
func NewPacketBuffering(plane *ebpf.BpfObjects, options BufferingOptions) (*PacketBuffering, error) {
	if plane == nil || options.Packets == 0 || options.PerSession == 0 || options.PerSession > options.Packets || options.Packets > 1<<20 || options.FrameBytes != ebpf.BufferFrameSize || options.Retention <= 0 {
		return nil, errors.New("invalid packet buffering capacity")
	}
	bytes := uint64(options.Packets) * uint64(options.FrameBytes)
	if bytes > uint64(int(^uint(0)>>1)) {
		return nil, errors.New("packet buffering storage exceeds address space")
	}
	baseTime, baseNS, err := bufferClockBase()
	if err != nil {
		return nil, err
	}
	if err := plane.ConfigureBufferPool(options.Packets); err != nil {
		return nil, err
	}
	sender, err := newBufferPacketSender(plane)
	if err != nil {
		return nil, err
	}
	reader, err := plane.NewBufferReader()
	if err != nil {
		return nil, errors.Join(err, sender.Close())
	}
	buffering := &PacketBuffering{prepareDone: make(chan struct{}), prepareStop: make(chan struct{}), plane: plane, sender: sender, complete: plane.BufferControl, reader: reader, options: options, owners: make(map[uint64]*bufferOwner), work: make(map[uint64]*bufferOwner), storage: make([]byte, int(bytes)), entries: make([]bufferedPacket, options.Packets), free: make([]uint32, options.Packets), stop: make(chan struct{}), progress: make(chan struct{}, 1), failures: make(chan error, 1), baseTime: baseTime, baseNS: baseNS}
	for i := range buffering.free {
		buffering.free[i] = uint32(len(buffering.free) - 1 - i)
	}
	buffering.wg.Add(2)
	go buffering.readPackets()
	go buffering.servicePackets()
	return buffering, nil
}

// Start initializes output after the API listener is ready, without extending
// readiness. Close cancels admission and installation without joining verification.
func (buffering *PacketBuffering) Start(ctx context.Context) <-chan struct{} {
	buffering.prepareOnce.Do(func() {
		buffering.prepareMu.Lock()
		loaderCtx, cancel := context.WithCancel(ctx)
		buffering.prepareCancel = cancel
		select {
		case <-buffering.prepareStop:
			cancel()
		default:
		}
		buffering.prepareMu.Unlock()
		buffering.plane.StartBufferPrograms(loaderCtx)
		go func() {
			if sender, ok := buffering.sender.(interface{ initialize(context.Context) error }); ok {
				buffering.prepareError = sender.initialize(loaderCtx)
			} else {
				buffering.prepareError = buffering.sender.Prepare()
			}
			if buffering.prepareError != nil {
				if loaderCtx.Err() != nil {
					log.Debug().Err(buffering.prepareError).Msg("Buffered forwarding initialization canceled")
				} else {
					log.Error().Err(buffering.prepareError).Msg("Buffered forwarding initialization failed for this process")
				}
			}
			close(buffering.prepareDone)
		}()
	})
	return buffering.prepareDone
}

// CancelPreparation interrupts admission waits immediately during shutdown.
// Verification owns its inputs and can finish later without being joined.
func (buffering *PacketBuffering) CancelPreparation() {
	buffering.prepareCancelOnce.Do(func() {
		buffering.prepareMu.Lock()
		defer buffering.prepareMu.Unlock()
		if buffering.prepareCancel != nil {
			buffering.prepareCancel()
		}
		if buffering.prepareStop != nil {
			close(buffering.prepareStop)
		}
	})
}

func (buffering *PacketBuffering) awaitPreparation() error {
	if buffering.prepareDone == nil {
		return nil
	}
	select {
	case <-buffering.prepareDone:
		return nil
	case <-buffering.prepareStop:
		return errors.New("packet buffering is closing")
	}
}

// Failures exposes a terminal reader/accounting error to process supervision.
func (buffering *PacketBuffering) Failures() <-chan error { return buffering.failures }

func (buffering *PacketBuffering) fail(err error) {
	select {
	case buffering.failures <- err:
	default:
	}
}

func (buffering *PacketBuffering) signal() {
	select {
	case buffering.progress <- struct{}{}:
	default:
	}
}

// SetPacketBuffering binds an endpoint before it admits buffering lifetimes.
func (conn *PfcpConnection) SetPacketBuffering(buffering *PacketBuffering) error {
	if buffering == nil {
		return errors.New("nil packet buffering runtime")
	}
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if conn.packetBuffers != nil && conn.packetBuffers != buffering {
		return errors.New("packet buffering runtime is already bound")
	}
	conn.packetBuffers = buffering
	return nil
}

// reservePacketBuffers creates metadata for an unpublished session. Packet
// storage is acquired only by XDP on arrival, independently of PFCP admission.
func (conn *PfcpConnection) reservePacketBuffers(association *NodeAssociation, session *Session) (*bufferOwner, error) {
	buffering := conn.packetBuffers
	if buffering == nil {
		return nil, errors.New("packet buffering runtime is unavailable")
	}
	for _, far := range session.FARs {
		if far.FarInfo.Action&4 != 0 {
			if err := buffering.prepareOutput(session.LocalSEID); err != nil {
				return nil, err
			}
			break
		}
	}
	if err := buffering.awaitPreparation(); err != nil {
		return nil, err
	}
	buffering.mu.Lock()
	if buffering.closed {
		buffering.mu.Unlock()
		return nil, fmt.Errorf("packet buffering reservation: %w", ebpf.ErrRuleCapacity)
	}
	owner := buffering.owners[session.LocalSEID]
	resuming := owner != nil
	if resuming && (!owner.canceled || owner.released || owner.conn != conn || owner.association != association || owner.retirement != nil) {
		buffering.mu.Unlock()
		return nil, errors.New("buffering session identity already reserved")
	}
	if !resuming {
		owner = &bufferOwner{conn: conn, association: association, session: session, noticeReady: true, cycles: make(map[uint32]*bufferCycle)}
		buffering.reserved++
		buffering.owners[session.LocalSEID] = owner
	}
	buffering.mu.Unlock()
	state := &packetBufferSession{owner: owner, cycles: make(map[uint32]*bufferCycle), revision: 1}
	var lanes []ebpf.BufferLane
	rollbackReservation := func() {
		if !resuming {
			buffering.mu.Lock()
			delete(buffering.owners, session.LocalSEID)
			buffering.reserved--
			buffering.mu.Unlock()
			return
		}
		// Fresh lanes are still unpublished; no packet can hold their cookie.
		for _, cycle := range state.cycles {
			_, discardErr := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferDiscard})
			_, releaseErr := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 6})
			if err := errors.Join(discardErr, releaseErr); err != nil {
				buffering.fail(err)
			} else {
				delete(owner.cycles, cycle.lane)
			}
		}
	}
	for farID, far := range session.FARs {
		if far.FarInfo.Action&4 == 0 {
			continue
		}
		var cycle *bufferCycle
		if resuming {
			var err error
			cycle, err = buffering.reserveCycle(owner, farID)
			if err != nil {
				rollbackReservation()
				return nil, err
			}
		} else {
			lane := uint32(len(lanes))
			owner.nextCookie++
			cycle = &bufferCycle{farID: farID, lane: lane, cookie: owner.nextCookie, head: noBufferedPacket}
			owner.cycles[lane] = cycle
			lanes = append(lanes, ebpf.BufferLane{Index: lane, Cookie: cycle.cookie, Mode: ebpf.BufferHold, UsesBAR: downlinkBARAssociated(session, far)})
		}
		state.cycles[farID] = cycle
		far.FarInfo.BufferSessionID, far.FarInfo.BufferCookie, far.FarInfo.BufferLane = session.LocalSEID, cycle.cookie, cycle.lane
		session.FARs[farID] = far
	}
	if !resuming {
		if err := buffering.plane.CreateBufferAnchor(session.LocalSEID, buffering.options.PerSession, lanes); err != nil {
			rollbackReservation()
			return nil, err
		}
	} else {
		// TS 29.244 V20.1.0 clause 5.2.4.2 permits BUFF at any time.
		// Keep old canceled lanes and their credits until normal reclamation;
		// resume the same anchor rather than reserving another session slot.
		owner.canceled, owner.terminal, owner.graced = false, false, false
		owner.grace = nil
		owner.noticeReady = true
	}
	session.buffers = state
	session.downlink = newDownlinkNotifications(0)
	return owner, nil
}

func (conn *PfcpConnection) activatePacketBuffers(owner *bufferOwner) {
	owner.active = true
	conn.applyDownlinkDurationLocked(owner.session, time.Now())
	conn.packetBuffers.noteQueued(owner)
}

// Publication can finish after the reader has already copied a record. Keep
// notification progress separate from consumption so the first committed
// packet remains the first one reported, including out-of-order ring delivery.
func (buffering *PacketBuffering) noteQueued(owner *bufferOwner) {
	if !owner.active || owner.canceled || !owner.noticeReady {
		return
	}
	session := owner.association.Sessions[owner.session.LocalSEID]
	if session == nil || session.buffers == nil || session.buffers.owner != owner {
		return
	}
	owner.noticeReady = false
	for _, cycle := range owner.cycles {
		if cycle == nil || cycle.canceled {
			continue
		}
		for range 65 {
			record, present, err := buffering.plane.ReadBufferNotice(owner.session.LocalSEID, cycle.cookie, cycle.lane)
			if err != nil {
				buffering.fail(err)
				break
			}
			if !present {
				break
			}
			arrived := buffering.baseTime.Add(time.Duration(record.ReceivedNS - buffering.baseNS))
			owner.conn.noteDownlinkPacketLocked(session, cycle.farID, record, arrived)
		}
	}
}

func (buffering *PacketBuffering) takePacket(owner *bufferOwner, cycle *bufferCycle, record ebpf.BufferRecord) (uint32, error) {
	if len(record.Packet) < 14 || uint64(len(record.Packet)) > uint64(buffering.options.FrameBytes) {
		return 0, errors.New("admitted packet exceeds frame capacity")
	}
	buffering.mu.Lock()
	defer buffering.mu.Unlock()
	if len(buffering.free) == 0 {
		return 0, errors.New("admitted packet exceeds reserved pool")
	}
	index := buffering.free[len(buffering.free)-1]
	buffering.free = buffering.free[:len(buffering.free)-1]
	offset := uint64(index) * uint64(buffering.options.FrameBytes)
	payload := buffering.storage[offset : offset+uint64(len(record.Packet)) : offset+uint64(buffering.options.FrameBytes)]
	copy(payload, record.Packet)
	record.Packet = payload
	arrived := buffering.baseTime
	if record.ReceivedNS >= buffering.baseNS && record.ReceivedNS-buffering.baseNS <= math.MaxInt64 {
		arrived = arrived.Add(time.Duration(record.ReceivedNS - buffering.baseNS))
	}
	buffering.entries[index] = bufferedPacket{record: record, arrived: arrived, next: noBufferedPacket, owner: owner, cycle: cycle}
	return index, nil
}

func (buffering *PacketBuffering) ownerSnapshot() []*bufferOwner {
	buffering.mu.Lock()
	defer buffering.mu.Unlock()
	owners := make([]*bufferOwner, 0, len(buffering.owners))
	for _, owner := range buffering.owners {
		owners = append(owners, owner)
	}
	return owners
}

func (buffering *PacketBuffering) readPackets() {
	defer buffering.wg.Done()
	for {
		record, err := buffering.reader.Read()
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				buffering.fail(fmt.Errorf("read admitted packet: %w", err))
			}
			return
		}
		buffering.consumePacket(record)
	}
}

func (buffering *PacketBuffering) consumePacket(record ebpf.BufferRecord) {
	buffering.mu.Lock()
	owner := buffering.owners[record.SessionID]
	buffering.mu.Unlock()
	if owner == nil {
		buffering.fail(errors.New("admitted packet has no reserved owner"))
		return
	}
	conn := owner.conn
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	cycle := owner.cycles[record.Lane]
	if cycle == nil || cycle.cookie != record.Cookie {
		buffering.fail(errors.New("admitted packet has an unknown lifetime"))
		return
	}
	if record.Sequence <= cycle.completed {
		return
	}
	previous := noBufferedPacket
	next := cycle.head
	for next != noBufferedPacket && buffering.entries[next].record.Sequence < record.Sequence {
		previous = next
		next = buffering.entries[next].next
	}
	if next != noBufferedPacket && buffering.entries[next].record.Sequence == record.Sequence {
		return
	}
	index, err := buffering.takePacket(owner, cycle, record)
	if err != nil {
		buffering.fail(err)
		return
	}
	buffering.entries[index].next = next
	if previous == noBufferedPacket {
		cycle.head = index
	} else {
		buffering.entries[previous].next = index
	}
	for {
		found := cycle.head
		for found != noBufferedPacket && buffering.entries[found].record.Sequence <= cycle.received {
			found = buffering.entries[found].next
		}
		if found == noBufferedPacket || buffering.entries[found].record.Sequence != cycle.received+1 {
			break
		}
		cycle.received++
	}
	if record.Notify {
		owner.noticeReady = true
	}
	buffering.noteQueued(owner)
	buffering.schedule(owner)
	buffering.signal()
}

func (buffering *PacketBuffering) servicePackets() {
	defer buffering.wg.Done()
	unpin, err := pinBufferOutputThread()
	if err != nil {
		buffering.fail(err)
		return
	}
	defer func() {
		if err := unpin(); err != nil {
			buffering.fail(err)
		}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-buffering.stop:
			return
		case <-ticker.C:
		}
		buffering.sampleMetrics()
		for range 512 {
			var id uint64
			if err := buffering.plane.BufferNoticeReady.NextKey(nil, &id); err != nil {
				if !errors.Is(err, cilium.ErrKeyNotExist) {
					buffering.fail(err)
				}
				break
			}
			if err := buffering.plane.BufferNoticeReady.Delete(id); err != nil && !errors.Is(err, cilium.ErrKeyNotExist) {
				buffering.fail(err)
				break
			}
			buffering.mu.Lock()
			owner := buffering.owners[id]
			buffering.mu.Unlock()
			if owner != nil {
				owner.conn.stateMu.Lock()
				owner.noticeReady = true
				buffering.schedule(owner)
				owner.conn.stateMu.Unlock()
			}
		}
		buffering.mu.Lock()
		owners := make([]*bufferOwner, 0, len(buffering.work))
		for _, owner := range buffering.work {
			owners = append(owners, owner)
		}
		buffering.mu.Unlock()
		for _, owner := range owners {
			buffering.serviceOutput(owner)
		}
	}
}

func (buffering *PacketBuffering) serviceOwner(owner *bufferOwner, now time.Time) {
	if owner.released || !owner.active && !owner.canceled {
		return
	}
	if owner.active && !owner.canceled {
		owner.conn.applyDownlinkDurationLocked(owner.session, now)
	}
	buffering.noteQueued(owner)
	if owner.canceled && owner.retirement != nil && bufferGraceDone(owner.resourcesDone) {
		// Successful resource reclamation proves that a failed creation's
		// deferred undo was repaired. Producer grace and packet ACKs still
		// gate the final owner/admission release below.
		owner.terminal = true
		for _, cycle := range owner.cycles {
			if cycle != nil && cycle.canceled {
				cycle.terminal = true
			}
		}
	}
	if owner.terminal && bufferGraceDone(owner.grace) {
		owner.graced = true
	}
	for _, cycle := range owner.cycles {
		if cycle == nil {
			continue
		}
		if cycle.draining && !cycle.canceled && !owner.canceled && !cycle.ready && bufferGraceDone(cycle.grace) {
			_, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferDrain, Ready: 1})
			if err != nil {
				buffering.ioFailure(cycle, now, err)
				continue
			}
			cycle.ready = true
			cycle.drainReady = time.Now()
		}
		for cycle.head != noBufferedPacket {
			packet := &buffering.entries[cycle.head]
			if packet.record.Sequence != cycle.completed+1 {
				break
			}
			if owner.canceled || cycle.canceled {
				canDiscard := owner.graced && owner.terminal || cycle.terminal && bufferGraceDone(cycle.grace)
				if !canDiscard {
					break
				}
			} else if !packet.sent && !buffering.packetExpired(owner, cycle, packet, now) {
				break
			}
			buffering.mu.Lock()
			_, err := buffering.complete(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Sequence: packet.record.Sequence, Downlink: packet.record.Downlink})
			if err != nil {
				buffering.mu.Unlock()
				buffering.ioFailure(cycle, now, fmt.Errorf("complete admitted buffer: %w", err))
				break
			}
			// Only acknowledged removals contribute. A successful hand-over
			// remains a send even when cancellation arrives before its ACK.
			reason := packet.discardReason
			if !packet.sent {
				reason = "expiry"
				if owner.canceled || cycle.canceled {
					reason = "cancellation"
				}
			}
			if reason != "" {
				bufferDiscardedPackets.WithLabelValues(reason).Inc()
				if reason == "expiry" {
					owner.discardExpiry++
				} else {
					owner.discardCancellation++
				}
			}
			cycle.failedAt = time.Time{}
			index := cycle.head
			cycle.head = packet.next
			cycle.completed = packet.record.Sequence
			buffering.entries[index] = bufferedPacket{}
			buffering.free = append(buffering.free, index)
			buffering.mu.Unlock()
			buffering.signal()
		}
		if !owner.canceled && cycle.draining && cycle.ready && !cycle.canceled && cycle.head == noBufferedPacket {
			buffering.retireDrainedCycle(owner, cycle)
		}
		if cycle.canceled && cycle.terminal && bufferGraceDone(cycle.grace) && cycle.head == noBufferedPacket {
			state, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 3})
			if err != nil {
				buffering.fail(err)
				continue
			}
			if state.Preparing == 0 && cycle.received == state.Produced && cycle.completed == state.Produced {
				if _, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 6}); err != nil {
					buffering.fail(err)
					continue
				}
				delete(owner.cycles, cycle.lane)
			}
		}
	}
	if owner.canceled && owner.graced {
		for _, cycle := range owner.cycles {
			if cycle == nil {
				continue
			}
			state, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 3})
			if err != nil {
				buffering.fail(err)
				return
			}
			if cycle.head != noBufferedPacket || state.Preparing != 0 || cycle.received != state.Produced || cycle.completed != state.Produced {
				return
			}
		}
		for _, cycle := range owner.cycles {
			if cycle == nil {
				continue
			}
			if _, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 6}); err != nil {
				buffering.fail(err)
				return
			}
		}
		if err := buffering.plane.BufferNoticeReady.Delete(owner.session.LocalSEID); err != nil && !errors.Is(err, cilium.ErrKeyNotExist) {
			buffering.fail(err)
			return
		}
		overflow, canceled, err := buffering.plane.BufferLifetimeDiscards(owner.session.LocalSEID)
		if err != nil {
			buffering.fail(err)
			return
		}
		if err := buffering.plane.BufferAnchors.Delete(owner.session.LocalSEID); err != nil {
			buffering.fail(err)
			return
		}
		log.Debug().Uint64("seid", owner.session.LocalSEID).Uint64("overflow", overflow).
			Uint64("expiry", owner.discardExpiry).Uint64("cancellation", canceled+owner.discardCancellation).
			Msg("Retire packet buffering lifetime")
		buffering.mu.Lock()
		if !owner.released {
			owner.released = true
			delete(buffering.owners, owner.session.LocalSEID)
			delete(buffering.work, owner.session.LocalSEID)
			buffering.reserved--
		}
		buffering.mu.Unlock()
		if owner.retirement != nil {
			owner.retirement.retired()
		}
		buffering.signal()
	}
}

// Close cancels producers, waits for their kernel grace and consumes all records
// before returning payload reservations. Reader closure unblocks its goroutine.
func (buffering *PacketBuffering) Close() error {
	buffering.closeOnce.Do(func() {
		buffering.CancelPreparation()
		buffering.mu.Lock()
		buffering.closed = true
		buffering.mu.Unlock()
		owners := buffering.ownerSnapshot()
		for _, owner := range owners {
			owner.conn.stateMu.Lock()
			waitBufferIO(owner)
			owner.canceled = true
			owner.terminal = true
			delete(owner.conn.downlinkSessions, owner.session.LocalSEID)
			if state := owner.session.downlink; state != nil {
				state.stopped = true
				clear(state.pending)
				state.pending = state.pending[:0]
			}
			for _, cycle := range owner.cycles {
				if cycle == nil {
					continue
				}
				_, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferDiscard})
				buffering.closeError = errors.Join(buffering.closeError, err)
				if err != nil {
					owner.terminal = false
				}
			}
			buffering.schedule(owner)
			owner.conn.stateMu.Unlock()
		}
		if len(owners) > 0 {
			err := buffering.plane.SynchronizeRules()
			buffering.closeError = errors.Join(buffering.closeError, err)
			if err == nil {
				for _, owner := range owners {
					owner.conn.stateMu.Lock()
					owner.graced = owner.terminal
					buffering.serviceOwner(owner, time.Now())
					owner.conn.stateMu.Unlock()
				}
			}
		}
		deadline := time.NewTimer(3 * time.Second)
	wait:
		for {
			buffering.mu.Lock()
			remaining := len(buffering.owners)
			buffering.mu.Unlock()
			if remaining == 0 {
				break
			}
			select {
			case <-buffering.progress:
			case <-time.After(20 * time.Millisecond):
			case <-deadline.C:
				buffering.closeError = errors.Join(buffering.closeError, errors.New("packet buffering reclamation did not finish"))
				break wait
			}
		}
		deadline.Stop()
		close(buffering.stop)
		buffering.closeError = errors.Join(buffering.closeError, buffering.reader.Close())
		buffering.wg.Wait()
		buffering.sampleMetrics()
		buffering.closeError = errors.Join(buffering.closeError, buffering.sender.Close())
	})
	return buffering.closeError
}

// TS 29.244 V20.1.0 clause 5.2.4.2: extended DL duration replaces
// ordinary retention. A valid retained packet gets a bounded output window when
// a new forwarding instruction ends buffering; it is not policed/accounted again.
func (buffering *PacketBuffering) packetExpired(owner *bufferOwner, cycle *bufferCycle, packet *bufferedPacket, now time.Time) bool {
	retention := buffering.options.Retention
	if cycle.draining && !cycle.drainStarted.IsZero() {
		if !packet.arrived.After(cycle.drainStarted) {
			if packet.record.Downlink && cycle.bufferedBAR {
				if !cycle.bufferedCutoff.IsZero() && packet.arrived.Before(cycle.bufferedCutoff) {
					return true
				}
				if !cycle.bufferedInfinite {
					if !cycle.bufferedUntil.IsZero() {
						if !cycle.drainStarted.Before(cycle.bufferedUntil) {
							return true
						}
					} else if !cycle.drainStarted.Before(packet.arrived.Add(retention)) {
						return true
					}
				}
			} else if !cycle.drainStarted.Before(packet.arrived.Add(retention)) {
				return true
			}
		}
		// Producer grace is a prerequisite for output, not part of its retry
		// budget. Newer packets must also wait behind this same drain barrier.
		// TS 29.244 V20.1.0 clause 5.2.4.2: forwarding uses the earlier processing.
		if cycle.drainReady.IsZero() {
			return false
		}
		start := cycle.drainReady
		if packet.arrived.After(start) {
			start = packet.arrived
		}
		return !now.Before(start.Add(retention))
	}
	if packet.record.Downlink && downlinkBARAssociated(owner.session, owner.session.FARs[cycle.farID]) && owner.session.downlink != nil {
		state := owner.session.downlink
		if !state.suppressBefore.IsZero() && packet.arrived.Before(state.suppressBefore) {
			return true
		}
		if state.infinite {
			return false
		}
		if !state.extendedUntil.IsZero() {
			return !now.Before(state.extendedUntil)
		}
	}
	return !now.Before(packet.arrived.Add(retention))
}

func waitBufferIO(owner *bufferOwner) {
	for _, cycle := range owner.cycles {
		if cycle != nil && cycle.ioDone != nil {
			<-cycle.ioDone
		}
	}
}

func (buffering *PacketBuffering) ioFailure(cycle *bufferCycle, now time.Time, err error) {
	if cycle.failedAt.IsZero() {
		cycle.failedAt = now
	}
	if now.Sub(cycle.failedAt) >= 3*time.Second {
		buffering.fail(err)
	}
}

// The sole output worker owns rendering/transmission. It closes I/O completion
// before taking stateMu again, so journal mutation can wait while holding it.
// A successful send is remembered independently of its idempotent kernel ACK.
func (buffering *PacketBuffering) serviceOutput(owner *bufferOwner) {
	conn := owner.conn
	for range 64 {
		conn.stateMu.Lock()
		buffering.serviceOwner(owner, time.Now())
		var chosen *bufferCycle
		var index uint32
		if owner.active && !owner.canceled && !owner.released {
			for _, cycle := range owner.cycles {
				if cycle == nil || !cycle.draining || !cycle.ready || cycle.canceled || cycle.head == noBufferedPacket {
					continue
				}
				packet := &buffering.entries[cycle.head]
				if packet.sent || packet.record.Sequence != cycle.completed+1 {
					continue
				}
				chosen, index = cycle, cycle.head
				break
			}
		}
		if chosen == nil {
			active := owner.canceled && !owner.released
			for _, cycle := range owner.cycles {
				if cycle != nil && (cycle.canceled || cycle.draining || cycle.head != noBufferedPacket) {
					active = true
					break
				}
			}
			if !active {
				buffering.mu.Lock()
				delete(buffering.work, owner.session.LocalSEID)
				buffering.mu.Unlock()
			}
			conn.stateMu.Unlock()
			return
		}
		current := owner.association.Sessions[owner.session.LocalSEID]
		if current == nil || current.buffers == nil || current.buffers.owner != owner || current.buffers.cycles[chosen.farID] != chosen {
			conn.stateMu.Unlock()
			return
		}
		far := current.FARs[chosen.farID]
		if far.FarInfo.Action&2 == 0 || far.FarInfo.BufferCookie != chosen.cookie {
			conn.stateMu.Unlock()
			return
		}
		record := buffering.entries[index].record
		done := make(chan struct{})
		chosen.ioDone = done
		conn.stateMu.Unlock()
		rendered, err := buffering.plane.RenderBufferedPacket(record, far.GlobalId)
		sent := false
		if err == nil && rendered.Action >= 2 && rendered.Action <= 4 {
			err = buffering.sender.Send(rendered)
			sent = err == nil
		} else if err == nil && rendered.Action <= 1 {
			sent = true
		}
		close(done)
		conn.stateMu.Lock()
		packet := &buffering.entries[index]
		if packet.owner == owner && packet.cycle == chosen && packet.record.Sequence == record.Sequence {
			if sent {
				packet.sent = true
				if rendered.Action <= 1 {
					packet.discardReason = "cancellation"
				}
				chosen.failedAt = time.Time{}
			} else if err != nil {
				buffering.ioFailure(chosen, time.Now(), err)
			}
		}
		chosen.ioDone = nil
		conn.stateMu.Unlock()
		if !sent {
			return
		}
	}
}

// schedule requires owner.conn.stateMu: the current session pointer can change
// when a journal publishes a replacement.
func (buffering *PacketBuffering) schedule(owner *bufferOwner) {
	buffering.mu.Lock()
	buffering.work[owner.session.LocalSEID] = owner
	buffering.mu.Unlock()
}

// Initialize before accepting any BUFF state. Packet storage is untouched on
// failure: no such lifetime has been published and no packet can be retained.
// TS 29.244 V20.1.0 clause 7.5.3, table 8.2.1-1: System failure (77).
func (buffering *PacketBuffering) prepareOutput(seid uint64) error {
	started := time.Now()
	select {
	case <-buffering.prepareDone:
	default:
		if err := buffering.awaitPreparation(); err != nil {
			return &requestIEError{ie.CauseSystemFailure, ie.ApplyAction, err}
		}
		log.Info().Uint64("seid", seid).Dur("duration", time.Since(started)).Msg("BUFF admission waited for background initialization")
	}
	err := buffering.prepareError
	if err == nil {
		err = buffering.sender.Prepare()
	}
	if err != nil {
		log.Error().Err(err).Uint64("seid", seid).Msg("Cannot initialize buffered forwarding; rejecting BUFF before publication")
		return &requestIEError{ie.CauseSystemFailure, ie.ApplyAction, fmt.Errorf("initialize buffered forwarding: %w", err)}
	}
	return nil
}
