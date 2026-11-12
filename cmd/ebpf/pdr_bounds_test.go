//go:build linux

package ebpf

import (
	"errors"
	"testing"
)

func TestPDRBoundsRejectWithoutTruncation(t *testing.T) {
	for _, test := range []struct {
		name string
		info PdrInfo
	}{
		{"SDF", PdrInfo{SdfFilter: make([]SdfFilter, MaxSDFFiltersPerPDR+1)}},
		{"QFI", PdrInfo{QFIs: make([]uint8, MaxQFIsPerPDR+1)}},
		{"QER", PdrInfo{QerIDs: []uint32{1, 2, 3, 4, 5}}},
		{"URR", PdrInfo{UrrIDs: []uint32{1, 2, 3, 4}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := encodePDR(test.info); !errors.Is(err, ErrRuleCapacity) {
				t.Fatalf("bound accepted: %v", err)
			}
		})
	}
}
func TestPDRBucketCapacityAndOwnership(t *testing.T) {
	bucket := IpEntrypointPdrInfo{SessionId: 9, Count: 4}
	for i := range bucket.Entries {
		bucket.Entries[i].PdrId = uint32(i + 1)
		bucket.Entries[i].Precedence = uint32(i + 1)
	}
	lookup := func(_ interface{}, out interface{}) error { *out.(*IpEntrypointPdrInfo) = bucket; return nil }
	if _, err := preparePDR(lookup, uint32(10), PdrInfo{SessionID: 9, PdrID: 5}); !errors.Is(err, ErrRuleCapacity) {
		t.Fatal(err)
	}
	if _, err := preparePDR(lookup, uint32(10), PdrInfo{SessionID: 99, PdrID: 1}); !errors.Is(err, ErrKeyOwned) {
		t.Fatal(err)
	}
	got, err := preparePDR(lookup, uint32(10), PdrInfo{SessionID: 9, PdrID: 2, Precedence: 0, FarId: 7})
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 4 || got.Entries[0].PdrId != 2 || got.Entries[0].Pdr.FarId != 7 {
		t.Fatalf("replacement failed: %+v", got)
	}
	for _, id := range []uint32{1, 3, 4} {
		found := false
		for _, pdr := range got.Entries {
			found = found || pdr.PdrId == id
		}
		if !found {
			t.Fatalf("replacement erased PDR %d", id)
		}
	}
}
