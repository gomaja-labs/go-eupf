// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// BufferFrameSize is the current fixed ring payload class.
const BufferFrameSize = config.BufferFrameBytes

const (
	// BufferHold admits packets while a FAR requests buffering.
	BufferHold uint32 = 1
	// BufferDrain keeps newer packets behind an outstanding flush.
	BufferDrain uint32 = 2
	// BufferForward is entered only after the producer/completion barrier.
	BufferForward uint32 = 3
	// BufferDiscard cancels admission for one immutable cookie.
	BufferDiscard uint32 = 4
)

type bufferFar struct {
	Cookie, Produced, Completed uint64
	Mode, Ready                 uint32
	Preparing, Reserved         uint32
	UsesBAR, Downlink           uint32
	Notices                     uint64
	AbsentNotice, AbsentSeen    uint32
	Seen                        uint64
	NoticeTime                  [65]uint64
	NoticePDR                   [65]uint16
	ReservedPDR                 [6]byte
}
type bufferKey struct {
	SessionID      uint64
	Lane, Reserved uint32
}
type bufferPool struct {
	Lock, Outstanding, Limit, Reserved uint32
	Dropped                            uint64
}
type bufferAnchor struct {
	Lock, Outstanding, Limit, BAROutstanding         uint32
	BARLimit, BARDLOutstanding, BARDLLimit, Reserved uint32
	BARUntilNS                                       uint64
}

// BufferLane identifies one FAR buffering lifetime independently of FAR slots.
type BufferLane struct {
	Index   uint32
	Cookie  uint64
	Mode    uint32
	UsesBAR bool
}

// CreateBufferAnchor initializes unpublished state. Published counters must only
// be changed by BufferControl, under the kernel spin lock.
func (b *BpfObjects) CreateBufferAnchor(session uint64, limit uint32, lanes []BufferLane) error {
	if b.BufferAnchors == nil || b.BufferAnchors.FD() < 0 {
		return errors.New("buffer maps are not loaded")
	}
	if session == 0 {
		return errors.New("zero buffering session identity")
	}
	anchor := bufferAnchor{Limit: limit, BARLimit: limit, BARDLLimit: limit}
	if err := b.BufferAnchors.Update(session, &anchor, cilium.UpdateNoExist); err != nil {
		return err
	}
	created := make([]bufferKey, 0, len(lanes))
	success := false
	defer func() {
		if !success {
			for _, key := range created {
				_ = b.BufferStates.Delete(key)
			}
			_ = b.BufferAnchors.Delete(session)
		}
	}()
	for _, lane := range lanes {
		if lane.Cookie == 0 || lane.Mode != BufferHold {
			return errors.New("invalid buffering lane")
		}
		state := bufferFar{Cookie: lane.Cookie, Mode: lane.Mode}
		if lane.UsesBAR {
			state.UsesBAR = 1
		}
		key := bufferKey{SessionID: session, Lane: lane.Index}
		if err := b.BufferStates.Update(key, &state, cilium.UpdateNoExist); err != nil {
			return err
		}
		created = append(created, key)
	}
	success = true
	return nil
}

// BufferCommand changes one lifetime or reads its admission/completion state.
// Operation zero acknowledges exactly one sequence; retries are idempotent.
type BufferCommand struct {
	SessionID, Cookie, Sequence                                       uint64
	Lane, Operation, Mode, Ready, Limit, Outstanding                  uint32
	Produced, Completed                                               uint64
	Preparing                                                         uint32
	BARLimit, BARDLLimit, BAROutstanding, BARDLOutstanding, DLPending uint32
	BARUntilNS                                                        uint64
	UsesBAR, Downlink                                                 bool
}

// BufferControl uses a private program to serialize with producer admission.
// It never replaces an anchor containing counters owned by running XDP calls.
func (b *BpfObjects) BufferControl(command BufferCommand) (BufferCommand, error) {
	if b.UpfBufferControlFunc == nil || b.UpfBufferControlFunc.FD() < 0 {
		return BufferCommand{}, errors.New("buffer control is not loaded")
	}
	key := bufferKey{SessionID: command.SessionID, Lane: command.Lane}
	if command.Operation == 5 {
		if err := b.BufferStates.Update(key, &bufferFar{}, cilium.UpdateNoExist); err != nil {
			return BufferCommand{}, err
		}
	}
	data := make([]byte, 96)
	binary.LittleEndian.PutUint64(data, command.SessionID)
	binary.LittleEndian.PutUint64(data[8:], command.Cookie)
	binary.LittleEndian.PutUint64(data[16:], command.Sequence)
	for i, v := range []uint32{command.Lane, command.Operation, command.Mode, command.Ready, command.Limit} {
		binary.LittleEndian.PutUint32(data[24+4*i:], v)
	}
	for i, v := range []uint32{command.BARLimit, command.BARDLLimit} {
		binary.LittleEndian.PutUint32(data[64+i*4:], v)
	}
	if command.UsesBAR {
		binary.LittleEndian.PutUint32(data[80:], 1)
	}
	if command.Downlink {
		binary.LittleEndian.PutUint32(data[84:], 1)
	}
	binary.LittleEndian.PutUint64(data[88:], command.BARUntilNS)
	output := make([]byte, 96)
	action, err := b.UpfBufferControlFunc.Run(&cilium.RunOptions{Data: data, DataOut: output})
	if err != nil || action != 1 {
		if command.Operation == 5 {
			_ = b.BufferStates.Delete(key)
		}
		if err != nil {
			return BufferCommand{}, fmt.Errorf("buffer control: %w", err)
		}
		return BufferCommand{}, errors.New("buffer control rejected stale or out-of-order command")
	}
	if command.Operation == 6 {
		if err := b.BufferStates.Delete(key); err != nil {
			return BufferCommand{}, err
		}
	}
	command.Mode = binary.LittleEndian.Uint32(output[32:])
	command.Ready = binary.LittleEndian.Uint32(output[36:])
	command.Limit = binary.LittleEndian.Uint32(output[40:])
	command.Outstanding = binary.LittleEndian.Uint32(output[44:])
	command.Produced = binary.LittleEndian.Uint64(output[48:])
	command.Completed = binary.LittleEndian.Uint64(output[56:])
	command.Preparing = uint32(binary.LittleEndian.Uint64(output[16:]))
	command.BARLimit = binary.LittleEndian.Uint32(output[64:])
	command.BARDLLimit = binary.LittleEndian.Uint32(output[68:])
	command.BAROutstanding = binary.LittleEndian.Uint32(output[72:])
	command.BARDLOutstanding = binary.LittleEndian.Uint32(output[76:])
	command.UsesBAR = binary.LittleEndian.Uint32(output[80:]) != 0
	command.DLPending = binary.LittleEndian.Uint32(output[84:])
	command.BARUntilNS = binary.LittleEndian.Uint64(output[88:])
	return command, nil
}

// JournalBufferControl stages admission mode or capacity with rule publication.
// Rollback preserves counters changed by packet producers and the ring reader.
func (tx *ruleTransaction) JournalBufferControl(command BufferCommand) error {
	if tx.finished || command.SessionID != tx.sessionID || (command.Operation != 1 && command.Operation != 2 && command.Operation != 7) {
		return errors.New("invalid journal buffering control")
	}
	query := command
	query.Operation, query.Mode, query.Ready = 3, 0, 0
	previous, err := tx.objects.BufferControl(query)
	if err != nil {
		return err
	}
	if tx.beforeWrite != nil {
		if err := tx.beforeWrite(); err != nil {
			return err
		}
	}
	if _, err := tx.objects.BufferControl(command); err != nil {
		return err
	}
	tx.dirty = true
	tx.undo = append(tx.undo, func() error {
		previous.Operation = 4
		if command.Operation == 2 || command.Operation == 7 {
			previous.Operation = command.Operation
		}
		_, err := tx.objects.BufferControl(previous)
		return err
	})
	return nil
}

// BufferGrace closes after a terminal publication or rollback and the kernel
// producer grace. Packet consumption and I/O completion remain separate signals.
// Closing this signal never waits for ring records in the grace worker.
func (tx *ruleTransaction) BufferGrace() <-chan struct{} {
	if tx.bufferGrace == nil {
		tx.bufferGrace = make(chan struct{})
	}
	return tx.bufferGrace
}

func (tx *ruleTransaction) finishBufferGrace() error {
	if tx.bufferGrace != nil {
		select {
		case <-tx.bufferGrace:
		default:
			close(tx.bufferGrace)
		}
	}
	return nil
}

// BufferRecord borrows its packet bytes from the reader until the next Read.
// Sequence defines arrival order at the per-session admission lock, per FAR.
type BufferRecord struct {
	SessionID, Cookie, Sequence, ReceivedNS                                         uint64
	Lane, PDRID, IngressIfindex                                                     uint32
	Marking                                                                         uint16
	Kind, NR, SourceInterface, OuterRemoval, OuterRemovalPresent, ExtensionDeletion uint8
	QFI                                                                             uint8
	QFIPresent                                                                      bool
	PPI                                                                             uint8
	Notify                                                                          bool
	Downlink                                                                        bool
	Packet                                                                          []byte
}

// BufferReader has one consumer. Close unblocks Read during shutdown.
type BufferReader struct {
	reader *ringbuf.Reader
	record ringbuf.Record
}

// NewBufferReader claims the application's single ring consumer for this load.
func (b *BpfObjects) NewBufferReader() (*BufferReader, error) {
	b.bufferMutex.Lock()
	defer b.bufferMutex.Unlock()
	if b.bufferReadClosed || b.BufferEvents == nil || b.BufferEvents.FD() < 0 {
		return nil, errors.New("buffer ring is not loaded")
	}
	if b.bufferReadClaimed {
		return nil, errors.New("buffer ring already has a consumer")
	}
	reader, err := ringbuf.NewReader(b.BufferEvents)
	if err != nil {
		return nil, fmt.Errorf("open buffering ring: %w", err)
	}
	b.bufferReadClaimed = true
	b.bufferReader = &BufferReader{reader: reader}
	return b.bufferReader, nil
}

// Close interrupts the ring reader and releases its mappings.
func (r *BufferReader) Close() error { return r.reader.Close() }

// SetDeadline bounds a read, including tests that require no notification.
func (r *BufferReader) SetDeadline(deadline time.Time) { r.reader.SetDeadline(deadline) }

// Read returns an admitted record, without allocating a payload copy.
func (r *BufferReader) Read() (BufferRecord, error) {
	if err := r.reader.ReadInto(&r.record); err != nil {
		return BufferRecord{}, err
	}
	return parseBufferRecord(r.record.RawSample)
}
func parseBufferRecord(raw []byte) (BufferRecord, error) {
	if len(raw) < 64 {
		return BufferRecord{}, fmt.Errorf("buffer record header: %w", io.ErrUnexpectedEOF)
	}
	length := binary.LittleEndian.Uint32(raw[40:])
	if length < 14 || length > BufferFrameSize || int(length) > len(raw)-64 {
		return BufferRecord{}, errors.New("invalid buffered frame length")
	}
	return BufferRecord{
		SessionID: binary.LittleEndian.Uint64(raw), Cookie: binary.LittleEndian.Uint64(raw[8:]), Sequence: binary.LittleEndian.Uint64(raw[16:]), ReceivedNS: binary.LittleEndian.Uint64(raw[24:]),
		Lane: binary.LittleEndian.Uint32(raw[32:]), PDRID: binary.LittleEndian.Uint32(raw[36:]), IngressIfindex: binary.LittleEndian.Uint32(raw[44:]), Marking: binary.LittleEndian.Uint16(raw[48:]),
		Kind: raw[50], NR: raw[51], SourceInterface: raw[52], OuterRemoval: raw[53], OuterRemovalPresent: raw[54], ExtensionDeletion: raw[55], QFI: raw[56], QFIPresent: raw[57] != 0, PPI: raw[58], Notify: raw[59] != 0, Downlink: raw[60]&1 != 0,
		Packet: raw[64 : 64+length],
	}, nil
}

// ConfigureBufferPool runs at startup before publishing any producers.
func (b *BpfObjects) ConfigureBufferPool(limit uint32) error {
	if b.BufferPool == nil || b.BufferPool.FD() < 0 || limit == 0 {
		return errors.New("invalid buffer pool")
	}
	return b.BufferPool.Put(uint32(0), bufferPool{Limit: limit})
}

// BufferPoolUsage includes queued ring records, retained payloads, and all drops
// caused by packet-storage limits. It never controls PFCP session admission.
func (b *BpfObjects) BufferPoolUsage() (outstanding uint32, dropped uint64, err error) {
	if b.BufferPool == nil || b.BufferPool.FD() < 0 {
		return 0, 0, errors.New("buffer pool is not loaded")
	}
	var pool bufferPool
	if err = b.BufferPool.Lookup(uint32(0), &pool); err != nil {
		return 0, 0, err
	}
	return pool.Outstanding, pool.Dropped, nil
}

// ReadBufferNotice consumes one durable first-packet observation. Its storage
// is independent of payload credits and of ring availability.
func (b *BpfObjects) ReadBufferNotice(session, cookie uint64, lane uint32) (BufferRecord, bool, error) {
	result, err := b.BufferControl(BufferCommand{SessionID: session, Cookie: cookie, Lane: lane, Operation: 8})
	if err != nil || result.Preparing == 0 {
		return BufferRecord{}, false, err
	}
	index := result.Preparing - 1
	return BufferRecord{SessionID: session, Cookie: cookie, Lane: lane, PDRID: result.Limit, ReceivedNS: result.Produced, QFI: uint8(index & 63), QFIPresent: index < 64, Notify: true, Downlink: true}, true, nil
}
