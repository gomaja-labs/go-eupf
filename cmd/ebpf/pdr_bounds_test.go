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
	b := loadDatapath(t)
	for id := uint32(1); id <= 4; id++ {
		if err := b.PutPdrUplink(100, PdrInfo{SessionID: 9, PdrID: id, Precedence: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.PutPdrUplink(100, PdrInfo{SessionID: 9, PdrID: 5}); !errors.Is(err, ErrRuleCapacity) {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(100, PdrInfo{SessionID: 99, PdrID: 1}); !errors.Is(err, ErrKeyOwned) {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(100, PdrInfo{SessionID: 9, PdrID: 2, Precedence: 0, FarId: 7}); err != nil {
		t.Fatal(err)
	}
	var got IpEntrypointPdrInfo
	if err := b.LookupUplinkPDR(100, &got); err != nil {
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

func TestPDRSDFPortPresenceIsExplicit(t *testing.T) {
	for _, present := range []bool{false, true} {
		entry, err := encodePDR(PdrInfo{SdfFilter: []SdfFilter{{Protocol: 47, PortsPresent: present}}})
		if err != nil {
			t.Fatal(err)
		}
		if (entry.SdfFilters[0].PortsPresent != 0) != present {
			t.Fatalf("port presence=%t encoded %d", present, entry.SdfFilters[0].PortsPresent)
		}
	}
}
