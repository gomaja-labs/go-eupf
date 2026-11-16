package ebpf

import "testing"

func TestRuleIDReservationDoesNotAllocateTemporaryHeap(t *testing.T) {
	tracker := NewIdTracker(65536)
	allocations := testing.AllocsPerRun(100, func() {
		id, err := tracker.GetNext()
		if err != nil || id != 1 {
			t.Fatalf("reserve smallest available ID: id=%d err=%v", id, err)
		}
		tracker.Release(id)
	})
	if allocations != 0 {
		t.Fatalf("reserve/release allocated temporary heap: %.1f allocations", allocations)
	}
}
