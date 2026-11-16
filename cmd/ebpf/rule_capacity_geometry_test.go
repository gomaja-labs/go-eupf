package ebpf

import (
	"math"
	"testing"
)

func TestPDRBucketCapacityBounds(t *testing.T) {
	for _, tc := range []struct{ keys, slots uint32 }{
		{1, 5}, {32, 129}, {64, 257}, {65, 259}, {128, 385}, {2048, 4225}, {131070, 262269}, {2147483583, math.MaxUint32},
	} {
		if slots, err := PDRBucketCapacity(tc.keys); err != nil || slots != tc.slots {
			t.Fatalf("keys=%d slots=%d want=%d: %v", tc.keys, slots, tc.slots, err)
		}
	}
	for _, keys := range []uint32{0, 2147483584, math.MaxUint32} {
		if _, err := PDRBucketCapacity(keys); err == nil {
			t.Fatalf("invalid capacity %d accepted", keys)
		}
	}
}
