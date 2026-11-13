// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
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

type bufferedPacket struct {
	record  ebpf.BufferRecord
	arrived time.Time
	next    uint32
	owner   *bufferOwner
	cycle   *bufferCycle
}
type bufferCycle struct {
	farID               uint32
	lane                uint32
	cookie              uint64
	head                uint32
	received, completed uint64
	notified            uint64
	canceled            bool
	draining, terminal  bool
	grace               <-chan struct{}
}
type packetBufferSession struct {
	owner    *bufferOwner
	cycles   map[uint32]*bufferCycle
	revision uint64
}
type bufferOwner struct {
	conn                               *PfcpConnection
	association                        *NodeAssociation
	session                            *Session
	cycles                             [ebpf.BufferFarLanes]*bufferCycle
	nextCookie                         uint64
	active, canceled, graced, released bool
	terminal                           bool
	grace                              <-chan struct{}
	retirement                         *sessionRetirement
}

// PacketBuffering owns one application ring reader and one bounded payload pool
// shared by N4/Sxa/Sxb. Session queues and their records are owned by stateMu;
// mu protects only shared registry, admission reservations and free slot IDs.
type PacketBuffering struct {
	plane      *ebpf.BpfObjects
	reader     *ebpf.BufferReader
	options    BufferingOptions
	mu         sync.Mutex
	owners     map[uint64]*bufferOwner
	reserved   uint32
	storage    []byte
	entries    []bufferedPacket
	free       []uint32
	closed     bool
	stop       chan struct{}
	progress   chan struct{}
	failures   chan error
	wg         sync.WaitGroup
	closeOnce  sync.Once
	closeError error
	baseTime   time.Time
	baseNS     uint64
}

// NewPacketBuffering preallocates payloads and starts the sole ring consumer.
// Rules remain unsupported until their complete publication/lifetime is wired.
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
	reader, err := plane.NewBufferReader()
	if err != nil {
		return nil, err
	}
	buffering := &PacketBuffering{plane: plane, reader: reader, options: options, owners: make(map[uint64]*bufferOwner), storage: make([]byte, int(bytes)), entries: make([]bufferedPacket, options.Packets), free: make([]uint32, options.Packets), stop: make(chan struct{}), progress: make(chan struct{}, 1), failures: make(chan error, 1), baseTime: baseTime, baseNS: baseNS}
	for i := range buffering.free {
		buffering.free[i] = uint32(len(buffering.free) - 1 - i)
	}
	buffering.wg.Add(2)
	go buffering.readPackets()
	go buffering.servicePackets()
	return buffering, nil
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

// reservePacketBuffers runs on a private unpublished session. The pool reserve
// is acquired before creating an anchor or publishing a buffering FAR.
func (conn *PfcpConnection) reservePacketBuffers(association *NodeAssociation, session *Session) (*bufferOwner, error) {
	buffering := conn.packetBuffers
	if buffering == nil {
		return nil, errors.New("packet buffering runtime is unavailable")
	}
	buffering.mu.Lock()
	if buffering.closed || buffering.reserved > buffering.options.Packets-buffering.options.PerSession {
		buffering.mu.Unlock()
		return nil, fmt.Errorf("packet buffering reservation: %w", ebpf.ErrRuleCapacity)
	}
	if buffering.owners[session.LocalSEID] != nil {
		buffering.mu.Unlock()
		return nil, errors.New("buffering session identity already reserved")
	}
	owner := &bufferOwner{conn: conn, association: association, session: session}
	state := &packetBufferSession{owner: owner, cycles: make(map[uint32]*bufferCycle), revision: 1}
	var lanes []ebpf.BufferLane
	for farID, far := range session.FARs {
		if far.FarInfo.Action&4 == 0 {
			continue
		}
		lane := uint32(len(lanes))
		if lane >= ebpf.BufferFarLanes {
			buffering.mu.Unlock()
			return nil, ebpf.ErrRuleCapacity
		}
		owner.nextCookie++
		cycle := &bufferCycle{farID: farID, lane: lane, cookie: owner.nextCookie, head: noBufferedPacket}
		owner.cycles[lane] = cycle
		state.cycles[farID] = cycle
		far.FarInfo.BufferSessionID = session.LocalSEID
		far.FarInfo.BufferCookie = cycle.cookie
		far.FarInfo.BufferLane = lane
		session.FARs[farID] = far
		lanes = append(lanes, ebpf.BufferLane{Index: lane, Cookie: cycle.cookie, Mode: ebpf.BufferHold})
	}
	buffering.reserved += buffering.options.PerSession
	buffering.owners[session.LocalSEID] = owner
	buffering.mu.Unlock()
	if err := buffering.plane.CreateBufferAnchor(session.LocalSEID, buffering.options.PerSession, lanes); err != nil {
		buffering.mu.Lock()
		delete(buffering.owners, session.LocalSEID)
		buffering.reserved -= buffering.options.PerSession
		buffering.mu.Unlock()
		return nil, err
	}
	session.buffers = state
	session.downlink = newDownlinkNotifications(int(buffering.options.PerSession))
	return owner, nil
}

func (conn *PfcpConnection) activatePacketBuffers(owner *bufferOwner) {
	owner.active = true
	if conn.downlinkSessions == nil {
		conn.downlinkSessions = make(map[uint64]*NodeAssociation)
	}
	conn.downlinkSessions[owner.session.LocalSEID] = owner.association
	conn.applyDownlinkDurationLocked(owner.session, time.Now())
	conn.packetBuffers.noteQueued(owner)
}

// Publication can finish after the reader has already copied a record. Keep
// notification progress separate from consumption so the first committed
// packet remains the first one reported, including out-of-order ring delivery.
func (buffering *PacketBuffering) noteQueued(owner *bufferOwner) {
	if !owner.active || owner.canceled {
		return
	}
	session := owner.association.Sessions[owner.session.LocalSEID]
	if session == nil || session.buffers == nil || session.buffers.owner != owner {
		return
	}
	for _, cycle := range owner.cycles {
		if cycle == nil || cycle.canceled {
			continue
		}
		for index := cycle.head; index != noBufferedPacket; index = buffering.entries[index].next {
			packet := &buffering.entries[index]
			if packet.record.Sequence <= cycle.notified {
				continue
			}
			if packet.record.Sequence > cycle.received {
				break
			}
			owner.conn.noteDownlinkPacketLocked(session, cycle.farID, packet.record, packet.arrived)
			cycle.notified = packet.record.Sequence
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
	payload := buffering.storage[offset : offset+uint64(len(record.Packet))]
	copy(payload, record.Packet)
	record.Packet = payload
	arrived := buffering.baseTime
	if record.ReceivedNS >= buffering.baseNS && record.ReceivedNS-buffering.baseNS <= math.MaxInt64 {
		arrived = arrived.Add(time.Duration(record.ReceivedNS - buffering.baseNS))
	}
	buffering.entries[index] = bufferedPacket{record: record, arrived: arrived, next: noBufferedPacket, owner: owner, cycle: cycle}
	return index, nil
}
func (buffering *PacketBuffering) releasePacket(index uint32) {
	buffering.mu.Lock()
	defer buffering.mu.Unlock()
	buffering.entries[index] = bufferedPacket{}
	buffering.free = append(buffering.free, index)
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
	if owner == nil || record.Lane >= ebpf.BufferFarLanes {
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
	buffering.noteQueued(owner)
	buffering.signal()
}

func (buffering *PacketBuffering) servicePackets() {
	defer buffering.wg.Done()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-buffering.stop:
			return
		case <-ticker.C:
		}
		for _, owner := range buffering.ownerSnapshot() {
			owner.conn.stateMu.Lock()
			buffering.serviceOwner(owner, time.Now())
			owner.conn.stateMu.Unlock()
		}
	}
}
func (buffering *PacketBuffering) serviceOwner(owner *bufferOwner, now time.Time) {
	if owner.released || !owner.active && !owner.canceled {
		return
	}
	buffering.noteQueued(owner)
	if owner.terminal && bufferGraceDone(owner.grace) {
		owner.graced = true
	}
	for _, cycle := range owner.cycles {
		if cycle == nil {
			continue
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
			} else if now.Before(packet.arrived.Add(buffering.options.Retention)) {
				break
			}
			_, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Sequence: packet.record.Sequence})
			if err != nil {
				buffering.fail(fmt.Errorf("complete discarded buffer: %w", err))
				break
			}
			index := cycle.head
			cycle.head = packet.next
			cycle.completed = packet.record.Sequence
			buffering.releasePacket(index)
			buffering.signal()
		}
		if cycle.canceled && cycle.terminal && bufferGraceDone(cycle.grace) && cycle.head == noBufferedPacket {
			state, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 3})
			if err != nil {
				buffering.fail(err)
				continue
			}
			if cycle.received == state.Produced && cycle.completed == state.Produced {
				if _, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 6}); err != nil {
					buffering.fail(err)
					continue
				}
				owner.cycles[cycle.lane] = nil
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
			if cycle.head != noBufferedPacket || cycle.received != state.Produced || cycle.completed != state.Produced {
				return
			}
		}
		if err := buffering.plane.BufferAnchors.Delete(owner.session.LocalSEID); err != nil {
			buffering.fail(err)
			return
		}
		buffering.mu.Lock()
		if !owner.released {
			owner.released = true
			delete(buffering.owners, owner.session.LocalSEID)
			buffering.reserved -= buffering.options.PerSession
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
		buffering.mu.Lock()
		buffering.closed = true
		buffering.mu.Unlock()
		owners := buffering.ownerSnapshot()
		for _, owner := range owners {
			owner.conn.stateMu.Lock()
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
	})
	return buffering.closeError
}
