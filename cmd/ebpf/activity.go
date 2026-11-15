package ebpf

import (
	"encoding/binary"
	"fmt"
)

// SessionActivityController owns counters independently of published PDR images.
// A slot must remain reserved until every referring image has passed rule grace.
type SessionActivityController interface {
	NewSessionActivity() (slot uint32, count uint64, err error)
	SessionActivityCount(slot uint32) (uint64, error)
	ReleaseSessionActivity(slot uint32)
}

func (b *BpfObjects) initSessionActivity() error {
	b.activityMutex.Lock()
	defer b.activityMutex.Unlock()
	memory, err := b.SessionActivity.Memory()
	if err != nil {
		return fmt.Errorf("map session activity: %w", err)
	}
	b.activityMemory = memory
	b.activityIDs = NewIdTracker(b.bufferSessions + 1)
	return nil
}

// NewSessionActivity reserves a counter without resetting its value: no old
// generation can be mistaken for fresh activity after the rule grace barrier.
func (b *BpfObjects) NewSessionActivity() (uint32, uint64, error) {
	b.activityMutex.Lock()
	defer b.activityMutex.Unlock()
	if b.activityIDs == nil {
		return 0, 0, fmt.Errorf("session activity map is closed")
	}
	slot, err := b.activityIDs.GetNext()
	if err != nil {
		return 0, 0, err
	}
	count, err := b.sessionActivityCount(slot)
	if err != nil {
		b.activityIDs.Release(slot)
		return 0, 0, err
	}
	return slot, count, nil
}

// SessionActivityCount reads one aligned 64-bit scalar from an mmapable array.
// cilium/ebpf Memory documents coherence for this individual-value access.
func (b *BpfObjects) SessionActivityCount(slot uint32) (uint64, error) {
	b.activityMutex.RLock()
	defer b.activityMutex.RUnlock()
	return b.sessionActivityCount(slot)
}
func (b *BpfObjects) sessionActivityCount(slot uint32) (uint64, error) {
	if slot == 0 || slot > b.bufferSessions || b.activityMemory == nil {
		return 0, fmt.Errorf("invalid session activity slot %d", slot)
	}
	var value [8]byte
	if _, err := b.activityMemory.ReadAt(value[:], int64(slot)*8); err != nil {
		return 0, fmt.Errorf("read session activity: %w", err)
	}
	return binary.NativeEndian.Uint64(value[:]), nil
}

// ReleaseSessionActivity returns a slot after transactional rule reclamation.
func (b *BpfObjects) ReleaseSessionActivity(slot uint32) {
	b.activityMutex.Lock()
	defer b.activityMutex.Unlock()
	if b.activityIDs != nil {
		b.activityIDs.Release(slot)
	}
}
