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

func TestRuleVersionCapacityBounds(t *testing.T) {
	for _, tc := range []struct{ live, versions, qer uint32 }{{1, 3, 4}, {4, 9, 13}, {64, 129, 193}, {65, 196 - 65, 196}, {128, 257, 385}, {1024, 1153, 2177}, {65535, 65664, 131199}, {131070, 131199, 262269}} {
		versions, err := RuleVersionCapacity(tc.live)
		if err != nil || versions != tc.versions {
			t.Fatalf("live=%d versions=%d want=%d: %v", tc.live, versions, tc.versions, err)
		}
		qer, err := QERVersionCapacity(tc.live)
		if err != nil || qer != tc.qer {
			t.Fatalf("live=%d QER=%d want=%d: %v", tc.live, qer, tc.qer, err)
		}
	}
	for _, live := range []uint32{0, math.MaxUint32} {
		if _, err := RuleVersionCapacity(live); err == nil {
			t.Fatalf("invalid live capacity %d accepted", live)
		}
	}
	if _, err := QERVersionCapacity(math.MaxUint32 / 2); err == nil {
		t.Fatal("QER anchor geometry overflow accepted")
	}
}
