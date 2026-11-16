package ebpf

import (
	"errors"
	"testing"
)

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

func TestRuleIDExhaustionReturnsCapacityWithoutAReservedID(t *testing.T) {
	for _, tc := range []struct {
		capacity uint32
		ids      []uint32
	}{{1, nil}, {2, []uint32{1}}, {5, []uint32{1, 2, 3, 4}}} {
		tracker := NewIdTracker(tc.capacity)
		for _, want := range tc.ids {
			if id, err := tracker.GetNext(); err != nil || id != want {
				t.Fatalf("capacity %d: got %d, %v; want %d", tc.capacity, id, err, want)
			}
		}
		if id, err := tracker.GetNext(); id != 0 || !errors.Is(err, ErrRuleCapacity) {
			t.Fatalf("exhausted capacity %d returned %d, %v", tc.capacity, id, err)
		}
	}
}
