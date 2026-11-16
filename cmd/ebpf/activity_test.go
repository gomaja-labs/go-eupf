//go:build linux

package ebpf

import (
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestSessionActivityCountsAllReceivedPathsOutsidePublishedRules(t *testing.T) {
	b := loadDatapath(t)
	slot, err := b.NewSessionActivity()
	if err != nil || slot == 0 {
		t.Fatal(slot, err)
	}
	for _, filtered := range []bool{false, true} {
		pdr := PdrInfo{PdrID: 1, Precedence: ^uint32(0), FarId: 2, ActivitySlot: slot, OuterHeaderRemovalPresent: true}
		if filtered {
			pdr.SdfFilter = []SdfFilter{anyDatapathFilter(SDFProtocolAny)}
		}
		if err := b.PutPdrUplink(10, pdr); err != nil {
			t.Fatal(err)
		}
		if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, pdr); err != nil {
			t.Fatal(err)
		}
		if err := b.PutDownlinkPdrIp6(net.ParseIP("2001:db8::2"), pdr); err != nil {
			t.Fatal(err)
		}
		var index IpEntrypointPdrIndex
		if err := b.PdrMapTeidIp4.Lookup(uint32(10), &index); err != nil {
			t.Fatal(err)
		}
		var before IpEntrypointPdrBucket
		if err := b.PdrBuckets.Lookup(index.Slot, &before); err != nil {
			t.Fatal(err)
		}
		for _, uplink := range []bool{false, true} {
			for _, v6 := range []bool{false, true} {
				packet := ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false))
				if v6 {
					packet = ethernetDatapath(t, layers.EthernetTypeIPv6, udpDatapath(t, true))
				}
				if uplink {
					packet = gtpDatapath(t, udpDatapath(t, v6), nil, 0x30, false)
				}
				if action, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil || action != 1 {
					t.Fatalf("DROP input action %d: %v", action, err)
				}
				if active, err := b.ConsumeSessionActivity(slot); err != nil || !active {
					t.Fatalf("missing activity filtered=%v uplink=%v v6=%v: %v", filtered, uplink, v6, err)
				}
				if active, err := b.ConsumeSessionActivity(slot); err != nil || active {
					t.Fatalf("activity repeated without another packet: %v", err)
				}
			}
		}
		var after IpEntrypointPdrBucket
		if err := b.PdrBuckets.Lookup(index.Slot, &after); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("packet activity mutated a published rule image")
		}
	}
	// Zero disables monitoring. Reuse starts clear after the previous rule
	// lifetime's grace period; callers must not release a live reference.
	b.ReleaseSessionActivity(slot)
	reused, err := b.NewSessionActivity()
	if err != nil || reused != slot {
		t.Fatal("activity slot reuse", reused, err)
	}
	if _, err := b.ConsumeSessionActivity(0); err == nil {
		t.Fatal("reserved slot zero was readable")
	}
}
