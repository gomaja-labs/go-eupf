//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func ipv6Extensions(t *testing.T, headers int, fragment uint16) []byte {
	t.Helper()
	inner := udpDatapath(t, true)
	extension := make([]byte, headers*8)
	for i := range headers {
		extension[i*8] = 60
	}
	if headers > 0 {
		extension[(headers-1)*8] = 17
		inner[6] = 60
	}
	if fragment != 0 {
		extension = append([]byte{17, 0, 0, 0, 0, 0, 0, 1}, extension...)
		binary.BigEndian.PutUint16(extension[2:], fragment)
		inner[6] = 44
	}
	inner = append(append(inner[:40:40], extension...), inner[40:]...)
	binary.BigEndian.PutUint16(inner[4:], uint16(len(inner)-40))
	return inner
}

func TestDatapathIPv6ExtensionClassification(t *testing.T) {
	b := loadDatapath(t)
	f := anyDatapathFilter(17)
	f.DstPortRange = PortRange{4321, 4321}
	for _, uplink := range []bool{false, true} {
		if uplink {
			if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, Precedence: 10, FarId: 2, UEIPv6: net.ParseIP("2001:db8::2"), UEIPv6Mask: net.CIDRMask(128, 128), UEDestination: true, SdfFilter: []SdfFilter{f}}); err != nil {
				t.Fatal(err)
			}
			if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, Precedence: 20, FarId: 1, OuterHeaderRemovalPresent: true}); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := b.PutDownlinkPdrIp6(net.ParseIP("2001:db8::2"), PdrInfo{PdrID: 1, Precedence: 10, FarId: 2, UEIPv6: net.ParseIP("2001:db8::2"), UEIPv6Mask: net.CIDRMask(128, 128), UEDestination: true, SdfFilter: []SdfFilter{f}}); err != nil {
				t.Fatal(err)
			}
			if err := b.PutDownlinkPdrIp6(net.ParseIP("2001:db8::2"), PdrInfo{PdrID: 2, Precedence: 20, FarId: 3, UEIPv6: net.ParseIP("2001:db8::2"), UEIPv6Mask: net.CIDRMask(128, 128), UEDestination: true}); err != nil {
				t.Fatal(err)
			}
		}
		for _, count := range []int{0, 1, 8, 9} {
			inner := ipv6Extensions(t, count, 0)
			packet := ethernetDatapath(t, layers.EthernetTypeIPv6, inner)
			if uplink {
				packet = gtpDatapath(t, inner, nil, 0x30, false)
			}
			action, _ := runDatapath(t, b, packet)
			if action != 1 {
				t.Errorf("uplink=%t extensions=%d bypassed DROP PDR: action=%d", uplink, count, action)
			}
		}
	}
}

func TestDatapathIPv6ExtensionsAndFragments(t *testing.T) {
	cases := []struct {
		name    string
		next    byte
		header  []byte
		blocked bool
		noports bool
	}{
		{"hop_options", 0, []byte{17, 0, 0, 0, 0, 0, 0, 0}, false, false},
		{"routing", 43, []byte{17, 0, 0, 0, 0, 0, 0, 0}, false, false},
		{"destination_options", 60, []byte{17, 0, 0, 0, 0, 0, 0, 0}, false, false},
		{"authentication", 51, []byte{17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false, false},
		{"atomic_fragment", 44, []byte{17, 0, 0, 0, 0, 0, 0, 1}, false, false},
		{"first_fragment", 44, []byte{17, 0, 0, 1, 0, 0, 0, 1}, false, false},
		{"nonfirst_fragment", 44, []byte{17, 0, 0, 16, 0, 0, 0, 1}, false, true},
		{"offset_one_fragment", 44, []byte{17, 0, 0, 8, 0, 0, 0, 1}, true, true},
		{"fragment_hides_next_header", 44, []byte{60, 0, 0, 16, 0, 0, 0, 1}, true, true},
		{"invalid_extension_span", 60, []byte{17, 255, 0, 0, 0, 0, 0, 0}, true, false},
	}
	b := loadDatapath(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inner := udpDatapath(t, true)
			inner[6] = c.next
			inner = append(append(inner[:40:40], c.header...), inner[40:]...)
			binary.BigEndian.PutUint16(inner[4:], uint16(len(inner)-40))
			for _, uplink := range []bool{false, true} {
				for _, matchingPort := range []bool{true, false} {
					f := anyDatapathFilter(17)
					f.PortsPresent = true
					f.DstPortRange = PortRange{4321, 4321}
					if !matchingPort {
						f.DstPortRange = PortRange{4322, 4322}
					}
					key := net.ParseIP("2001:db8::2")
					high := PdrInfo{PdrID: 1, Precedence: 10, FarId: 2, SdfFilter: []SdfFilter{f}, UEIPv6: key, UEIPv6Mask: net.CIDRMask(128, 128), UEDestination: true}
					low := PdrInfo{PdrID: 2, Precedence: 20, FarId: 3, UEIPv6: key, UEIPv6Mask: net.CIDRMask(128, 128), UEDestination: true}
					packet := ethernetDatapath(t, layers.EthernetTypeIPv6, inner)
					if uplink {
						high.UEIPv6 = nil
						low.UEIPv6 = nil
						low.FarId = 1
						low.OuterHeaderRemovalPresent = true
						if err := b.PutPdrUplink(10, high); err != nil {
							t.Fatal(err)
						}
						if err := b.PutPdrUplink(10, low); err != nil {
							t.Fatal(err)
						}
						packet = gtpDatapath(t, inner, nil, 0x30, false)
					} else {
						if err := b.PutDownlinkPdrIp6(key, high); err != nil {
							t.Fatal(err)
						}
						if err := b.PutDownlinkPdrIp6(key, low); err != nil {
							t.Fatal(err)
						}
					}
					action, _ := runDatapath(t, b, packet)
					wantDrop := c.blocked || matchingPort && !c.noports
					if (action == 1) != wantDrop || action == 0 {
						t.Errorf("uplink=%t port_match=%t drop=%t action=%d", uplink, matchingPort, wantDrop, action)
					}
				}
			}
		})
	}
}

func TestDatapathNonfirstFragmentExplicitAllPorts(t *testing.T) {
	b := loadDatapath(t)
	inner := ipv6Extensions(t, 0, 16)
	for _, explicit := range []bool{false, true} {
		filter := anyDatapathFilter(17)
		filter.PortsPresent = explicit
		if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, Precedence: 10, FarId: 2, SdfFilter: []SdfFilter{filter}}); err != nil {
			t.Fatal(err)
		}
		if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, Precedence: 20, FarId: 1, OuterHeaderRemovalPresent: true}); err != nil {
			t.Fatal(err)
		}
		action, _ := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false))
		if (action == 1) == explicit || action == 0 {
			t.Fatalf("explicit ports=%t action=%d", explicit, action)
		}
	}
}
