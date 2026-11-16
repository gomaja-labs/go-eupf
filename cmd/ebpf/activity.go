package ebpf

import (
	"encoding/binary"
	"fmt"
)

// SessionActivityController owns packet-set activity bits outside published PDR images.
// A slot must remain reserved until every referring image has passed rule grace.
type SessionActivityController interface {
	NewSessionActivity() (slot uint32, err error)
	ConsumeSessionActivity(slot uint32) (bool, error)
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

// NewSessionActivity reserves and clears a bit after its previous lifetime's
// rule grace barrier. No old packet writer can touch a newly allocated slot.
func (b *BpfObjects) NewSessionActivity() (uint32, error) {
	b.activityMutex.Lock()
	defer b.activityMutex.Unlock()
	if b.activityIDs == nil {
		return 0, fmt.Errorf("session activity map is closed")
	}
	slot, err := b.activityIDs.GetNext()
	if err != nil {
		return 0, err
	}
	if err := b.clearSessionActivity(slot); err != nil {
		b.activityIDs.Release(slot)
		return 0, err
	}
	return slot, nil
}

// ConsumeSessionActivity clears only an observed set bit. Packet CPUs only
// store one, so a late writer cannot erase a newer observation. The caller must
// timestamp activity after this call: even a packet whose store races with the
// clear is then included in that observation (TS 29.244 V20.1.0 clause 5.11.2).
// A zero observation is never cleared; a concurrent late store reaches the next
// poll. Serialize consumers and slot reuse with activityMutex.
func (b *BpfObjects) ConsumeSessionActivity(slot uint32) (bool, error) {
	b.activityMutex.Lock()
	defer b.activityMutex.Unlock()
	value, err := b.sessionActivityValue(slot)
	if err != nil || value == 0 {
		return false, err
	}
	if err := b.clearSessionActivity(slot); err != nil {
		return false, err
	}
	return true, nil
}

func (b *BpfObjects) clearSessionActivity(slot uint32) error {
	if slot == 0 || slot > b.bufferSessions || b.activityMemory == nil {
		return fmt.Errorf("invalid session activity slot %d", slot)
	}
	var zero [8]byte
	if _, err := b.activityMemory.WriteAt(zero[:], int64(slot)*8); err != nil {
		return fmt.Errorf("clear session activity: %w", err)
	}
	return nil
}

func (b *BpfObjects) sessionActivityValue(slot uint32) (uint64, error) {
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
