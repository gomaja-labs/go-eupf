//go:build linux

package ebpf

import (
	"errors"
	"net"
	"testing"
	"unsafe"

	cilium "github.com/cilium/ebpf"
)

func TestKernelPDRPlanChecksOwnershipCapacityAndPrefixes(t *testing.T) {
	b := NewBpfObjects()
	makeMap := func(kind cilium.MapType, keySize uint32) *cilium.Map {
		m, err := cilium.NewMap(&cilium.MapSpec{Type: kind, KeySize: keySize, ValueSize: uint32(unsafe.Sizeof(IpEntrypointPdrInfo{})), MaxEntries: 2, Flags: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	b.PdrMapTeidIp4 = makeMap(cilium.Hash, 4)
	b.PdrMapDownlinkIp4 = makeMap(cilium.Hash, 4)
	b.PdrMapDownlinkIp6 = makeMap(cilium.LPMTrie, 20)
	for id := uint32(1); id <= 2; id++ {
		if err := b.PutPdrUplink(id, PdrInfo{SessionID: 100 + uint64(id), PdrID: 1, FarId: 1}); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name string, owner uint64, keys []PDRKey, want error) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			err := b.CheckPDRPlan(owner, keys)
			if !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
		})
	}
	check("foreign_TEID", 9, []PDRKey{{ID: 1, TEID: 1}}, ErrKeyOwned)
	check("key_map_capacity", 9, []PDRKey{{ID: 1, TEID: 3}}, ErrRuleCapacity)
	check("replacement_final_capacity", 101, []PDRKey{{ID: 1, TEID: 3}}, nil)
	var crowded []PDRKey
	for id := uint32(1); id <= MaxPDRsPerKey+1; id++ {
		crowded = append(crowded, PDRKey{ID: id, TEID: 1})
	}
	check("per_key_capacity", 101, crowded, ErrRuleCapacity)
	if err := b.PutPdrDownlink(net.ParseIP("2001:db8::1"), PdrInfo{SessionID: 101, PdrID: 1, UEIPv6Mask: net.CIDRMask(64, 128)}); err != nil {
		t.Fatal(err)
	}
	check("foreign_prefix", 9, []PDRKey{{ID: 1, IPv6: net.ParseIP("2001:db8::2"), IPv6Mask: net.CIDRMask(128, 128)}}, ErrKeyOwned)
	check("overlapping_final_prefixes", 101, []PDRKey{{ID: 1, IPv6: net.ParseIP("2001:db8::"), IPv6Mask: net.CIDRMask(64, 128)}, {ID: 2, IPv6: net.ParseIP("2001:db8::2"), IPv6Mask: net.CIDRMask(128, 128)}}, ErrUnsupportedRuleContent)
	// Preflight must never have changed the kernel's original key ownership.
	for key := uint32(1); key <= 2; key++ {
		var value IpEntrypointPdrInfo
		if err := b.PdrMapTeidIp4.Lookup(key, &value); err != nil || value.SessionId != 100+uint64(key) {
			t.Fatalf("preflight changed key %d: %+v %v", key, value, err)
		}
	}
}
