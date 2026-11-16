package ebpf

import (
	"fmt"
	"math"
	"slices"
	"sync"
)

// RuleVersionCapacity reserves a live ID for each configured rule, slot zero,
// and at most two transaction batches for replacement and retirement. The shared
// journal serializes publications and admits at most MaxRulesPerSession rules
// of each type. Additional retired batches use the bounded capacity wait.
func RuleVersionCapacity(live uint32) (uint32, error) {
	total := uint64(live) + min(uint64(live), uint64(2*MaxRulesPerSession)) + 1
	if live == 0 || total > math.MaxUint32 {
		return 0, fmt.Errorf("invalid live rule capacity %d", live)
	}
	return uint32(total), nil
}

// QERVersionCapacity also retains one stable policer anchor per live QER.
// The first configuration may share that slot; a replacement cannot reuse it.
func QERVersionCapacity(live uint32) (uint32, error) {
	base, err := RuleVersionCapacity(live)
	if err != nil {
		return 0, err
	}
	total := uint64(base) + uint64(live)
	if total > math.MaxUint32 {
		return 0, fmt.Errorf("invalid live QER capacity %d", live)
	}
	return uint32(total), nil
}

func newVersionIDTracker(live, slots uint32) *IdTracker {
	tracker := NewIdTracker(slots)
	tracker.live = make([]uint64, (uint64(slots)+63)/64)
	tracker.liveLimit = live
	return tracker
}
func (t *IdTracker) isLive(id uint32) bool {
	return id < t.maxSize && t.live != nil && t.live[id/64]&(uint64(1)<<(id%64)) != 0
}
func (t *IdTracker) markLive(id uint32) {
	if t.live != nil && !t.isLive(id) {
		t.live[id/64] |= uint64(1) << (id % 64)
		t.liveCount++
	}
}
func (t *IdTracker) unmarkLive(id uint32) {
	if t.isLive(id) {
		t.live[id/64] &^= uint64(1) << (id % 64)
		t.liveCount--
	}
}
func (t *IdTracker) projectedLive(added, removed []uint32) int64 {
	count := int64(t.liveCount)
	for _, id := range added {
		if !t.isLive(id) {
			count++
		}
	}
	for _, id := range removed {
		if t.isLive(id) || slices.Contains(added, id) {
			count--
		}
	}
	return count
}
func appendVersionRemoval(ids []uint32, id uint32) []uint32 {
	if !slices.Contains(ids, id) {
		return append(ids, id)
	}
	return ids
}
func (tx *ruleTransaction) checkLiveVersionCapacity() error {
	b := tx.objects
	for i, t := range []*IdTracker{b.farIdTracker, b.qerIdTracker, b.urrIdTracker} {
		if len(tx.versionAdditions(i))+len(tx.removedVersions[i]) == 0 {
			continue
		}
		if t == nil || t.live == nil {
			continue
		}
		mu := []*sync.Mutex{&b.farMutex, &b.qerMutex, &b.urrMutex}[i]
		mu.Lock()
		count := t.projectedLive(tx.versionAdditions(i), tx.removedVersions[i])
		mu.Unlock()
		if count < 0 || count > int64(t.liveLimit) {
			return ErrRuleCapacity
		}
	}
	return nil
}
func (tx *ruleTransaction) commitLiveVersions() {
	b := tx.objects
	for i, t := range []*IdTracker{b.farIdTracker, b.qerIdTracker, b.urrIdTracker} {
		if len(tx.versionAdditions(i))+len(tx.removedVersions[i]) == 0 {
			continue
		}
		if t == nil || t.live == nil {
			continue
		}
		mu := []*sync.Mutex{&b.farMutex, &b.qerMutex, &b.urrMutex}[i]
		mu.Lock()
		for _, id := range tx.versionAdditions(i) {
			t.markLive(id)
		}
		for _, id := range tx.removedVersions[i] {
			t.unmarkLive(id)
		}
		mu.Unlock()
	}
}
func (tx *ruleTransaction) versionAdditions(kind int) []uint32 {
	switch kind {
	case 0:
		return tx.allocatedFAR
	case 1:
		return tx.allocatedQER
	default:
		return tx.allocatedURR
	}
}
