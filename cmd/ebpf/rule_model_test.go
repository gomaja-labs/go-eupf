//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestDatapathAdditionalSdfPreservesExistingRule(t *testing.T) {
	// TS 29.244 V20.1.0 clause 5.2.1: independently provisioned PDRs
	// sharing a session key must both remain selectable.
	b := loadDatapath(t)
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{OuterHeaderRemovalPresent: true, PdrID: 1, FarId: 1, QerIDs: []uint32{1}, SdfFilter: []SdfFilter{anyDatapathFilter(17)}}); err != nil {
		t.Fatal(err)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	before, _ := runDatapath(t, b, packet)
	if before == 1 {
		t.Fatalf("first PDR did not forward before insertion: %d", before)
	}
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, FarId: 2, QerIDs: []uint32{1}, SdfFilter: []SdfFilter{anyDatapathFilter(6)}}); err != nil {
		t.Fatal(err)
	}
	after, _ := runDatapath(t, b, packet)
	if after != before {
		t.Fatalf("adding TCP PDR changed UDP forwarding: before=%d after=%d", before, after)
	}
}

func TestDatapathAbsentOuterRemovalKeepsTunnel(t *testing.T) {
	b := loadDatapath(t)
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, FarId: 1}); err != nil {
		t.Fatal(err)
	}
	_, out := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false))
	if gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default).Layer(layers.LayerTypeGTPv1U) == nil {
		t.Fatal("absent Outer Header Removal still decapsulated")
	}
}
func TestDatapathKnownKeyDropsOtherIPProtocol(t *testing.T) {
	b := loadDatapath(t)
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: 253, SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{192, 0, 2, 2}}
	if err := b.PutPdrDownlink(ip.DstIP, PdrInfo{PdrID: 1, FarId: 2}); err != nil {
		t.Fatal(err)
	}
	action, _ := runDatapath(t, b, ethernetDatapath(t, layers.EthernetTypeIPv4, serializeDatapath(t, ip, gopacket.Payload([]byte{1, 2, 3, 4}))))
	if action != 1 {
		t.Fatalf("known key bypassed PDR for IP protocol 253: action=%d", action)
	}
}

func TestDatapathOrderedCompletePDI(t *testing.T) {
	b := loadDatapath(t)
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	put := func(p PdrInfo) {
		t.Helper()
		if err := b.PutPdrUplink(10, p); err != nil {
			t.Fatal(err)
		}
	}
	udp := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	first := PdrInfo{SessionID: 9, PdrID: 1, Precedence: 100, OuterHeaderRemovalPresent: true, FarId: 1, SdfFilter: []SdfFilter{anyDatapathFilter(17)}}
	second := PdrInfo{SessionID: 9, PdrID: 2, Precedence: 10, FarId: 2, UEIPv4: net.IP{192, 0, 2, 99}, SdfFilter: []SdfFilter{anyDatapathFilter(17)}}
	put(first)
	put(second)
	check := func(name string, packet []byte, drop bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			action, _ := runDatapath(t, b, packet)
			if (action == 1) != drop {
				t.Fatalf("action=%d drop=%v", action, drop)
			}
		})
	}
	check("UE_constraint_falls_through", udp, false)
	second.UEIPv4 = net.IP{198, 51, 100, 1}
	second.QFIs = []uint8{9}
	put(second)
	check("absent_QFI_falls_through", udp, false)
	marked := gtpDatapath(t, udpDatapath(t, false), []byte{0, 0, 0, 0x85, 1, 0x10, 9, 0}, 0x34, false)
	check("all_fields_match_higher_precedence", marked, true)
	first.Precedence = 5
	put(first)
	check("precedence_update_changes_winner", marked, false)
	if err := b.DeletePdrUplink(10, 9, 1); err != nil {
		t.Fatal(err)
	}
	check("delete_only_selected_PDR", marked, true)
	check("known_key_unmatched_drops", udp, true)
	second.QFIs = []uint8{0}
	put(second)
	check("zero_QFI_requires_presence", udp, true)
	zero := gtpDatapath(t, udpDatapath(t, false), []byte{0, 0, 0, 0x85, 1, 0x10, 0, 0}, 0x34, false)
	second.FarId = 1
	second.OuterHeaderRemovalPresent = true
	put(second)
	check("present_zero_QFI_matches", zero, false)
	second.QFIs = nil
	second.SdfFilter = []SdfFilter{anyDatapathFilter(6), anyDatapathFilter(17)}
	put(second)
	check("repeated_SDF_is_OR", udp, false)
	second.SourceInterfacePresent = true
	second.SourceInterface = 1
	put(second)
	check("source_interface_is_conjunctive", udp, true)
}

func TestDatapathEveryQERGateAndRateApplies(t *testing.T) {
	b := loadDatapath(t)
	p := PdrInfo{PdrID: 1, Precedence: ^uint32(0), OuterHeaderRemovalPresent: true, FarId: 1, QerIDs: []uint32{1, 2}}
	if err := b.PutPdrUplink(10, p); err != nil {
		t.Fatal(err)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	for index, slot := range []uint32{1, 2} {
		t.Run(fmt.Sprintf("gate_%d", index), func(t *testing.T) {
			putDatapath(t, b.QerMap.Put, slot, &IpEntrypointQerInfo{UlGateStatus: 1})
			action, _ := runDatapath(t, b, packet)
			if action != 1 {
				t.Fatalf("QER slot %d gate ignored: %d", slot, action)
			}
			putDatapath(t, b.QerMap.Put, slot, &IpEntrypointQerInfo{})
		})
	}
	putDatapath(t, b.QerMap.Put, uint32(2), &IpEntrypointQerInfo{UlMaximumBitrate: 1})
	if action, _ := runDatapath(t, b, packet); action == 1 {
		t.Fatal("first rate-limited PDU not admitted")
	}
	if action, _ := runDatapath(t, b, packet); action != 1 {
		t.Fatal("second QER rate ignored")
	}
}

func TestDatapathRAUsesOriginatingSessionTunnel(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.QerMap.Put, uint32(2), &IpEntrypointQerInfo{QfiPresent: 1, Qfi: 9, Rqi: 1})
	putDatapath(t, b.QerMap.Put, uint32(3), &IpEntrypointQerInfo{QfiPresent: 1, Qfi: 7})
	// A competing destination lookup must not redirect the response to another session.
	if err := b.PutPdrDownlink(net.ParseIP("fe80::1234"), PdrInfo{SessionID: 99, PdrID: 1, FarId: 2}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.ParseIP("ff02::1"), PdrInfo{SessionID: 99, PdrID: 2, FarId: 2}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, Precedence: ^uint32(0), OuterHeaderRemovalPresent: true, FarId: 1, ReturnFarID: 3, ReturnQerIDs: []uint32{1, 2, 3}, ReturnNR: true}); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"fe80::1234", "::"} {
		t.Run(source, func(t *testing.T) {
			_, out := runDatapath(t, b, gtpDatapath(t, rsDatapath(t, source, 255, 0), nil, 0x30, false))
			decoded := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			outer, ok := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || !outer.DstIP.Equal(net.IP{198, 18, 1, 2}) {
				t.Fatalf("wrong return endpoint: %v", outer)
			}
			tunnel, ok := decoded.Layer(layers.LayerTypeGTPv1U).(*layers.GTPv1U)
			if !ok || tunnel.TEID != 200 {
				t.Fatalf("wrong return tunnel: %v", tunnel)
			}
			// PSC is four octets after the optional GTP word: first marked QER wins.
			raw := tunnel.Contents
			if len(raw) < 16 || raw[11] != 0x85 || raw[14]&0x7f != 0x49 {
				t.Fatal("RA lacks first QFI/RQI marking")
			}
			if decoded.Layer(layers.LayerTypeICMPv6RouterAdvertisement) == nil {
				t.Fatal("no encapsulated RA")
			}
		})
	}
}

func TestDatapathEveryDownlinkQERApplies(t *testing.T) {
	b := loadDatapath(t)
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{PdrID: 1, FarId: 3, QerIDs: []uint32{1, 2}}); err != nil {
		t.Fatal(err)
	}
	packet := ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false))
	for _, slot := range []uint32{1, 2} {
		t.Run(fmt.Sprintf("gate_%d", slot), func(t *testing.T) {
			putDatapath(t, b.QerMap.Put, slot, &IpEntrypointQerInfo{DlGateStatus: 1})
			if action, _ := runDatapath(t, b, packet); action != 1 {
				t.Fatalf("DL QER %d gate ignored", slot)
			}
			putDatapath(t, b.QerMap.Put, slot, &IpEntrypointQerInfo{})
		})
	}
	putDatapath(t, b.QerMap.Put, uint32(2), &IpEntrypointQerInfo{DlMaximumBitrate: 1})
	if action, _ := runDatapath(t, b, packet); action == 1 {
		t.Fatal("first DL rate-limited PDU dropped")
	}
	if action, _ := runDatapath(t, b, packet); action != 1 {
		t.Fatal("second DL QER rate ignored")
	}
}

func TestDatapathCoreGTPIngressUsesN9Address(t *testing.T) {
	b := loadDatapath(t)
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, Precedence: ^uint32(0), FarId: 1, OuterHeaderRemovalPresent: true, SourceInterfacePresent: true, SourceInterface: 1}); err != nil {
		t.Fatal(err)
	}
	n3 := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	if action, _ := runDatapath(t, b, n3); action != 1 {
		t.Fatal("Core PDI matched N3 ingress")
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 18, 1, 2}, DstIP: net.IP{192, 0, 2, 2}}
	udp := &layers.UDP{SrcPort: 2152, DstPort: 2152}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	n9 := ethernetDatapath(t, layers.EthernetTypeIPv4, serializeDatapath(t, ip, udp, gopacket.Payload(n3[42:])))
	action, out := runDatapath(t, b, n9)
	if action == 1 || len(out) >= len(n9) {
		t.Fatalf("Core PDI failed N9 ingress: action=%d", action)
	}
}

func TestDatapathAssignedSDFMatchesTerminalAddressSet(t *testing.T) {
	b := loadDatapath(t)
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	filter := anyDatapathFilter(SDFProtocolAny)
	filter.DstAddress.Type = 3
	p := PdrInfo{PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true, AssignedIPv4: net.ParseIP("198.51.100.2"), AssignedIPv6: net.ParseIP("2001:db8::"), AssignedIPv6Mask: net.CIDRMask(64, 128), SdfFilter: []SdfFilter{filter}}
	check := func(v6 bool, drop bool) {
		t.Helper()
		action, _ := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, v6), nil, 0x30, false))
		if (action == 1) != drop {
			t.Fatalf("v6=%v action=%d wantDrop=%v", v6, action, drop)
		}
	}
	if err := b.PutPdrUplink(10, p); err != nil {
		t.Fatal(err)
	}
	check(false, false)
	check(true, false)
	p.AssignedIPv4 = net.ParseIP("198.51.100.99")
	p.AssignedIPv6 = net.ParseIP("2001:db8:1::")
	if err := b.PutPdrUplink(10, p); err != nil {
		t.Fatal(err)
	}
	check(false, true)
	check(true, true)
	p.AssignedIPv4, p.AssignedIPv6 = nil, nil
	if err := b.PutPdrUplink(10, p); err != nil {
		t.Fatal(err)
	}
	check(false, true)
	check(true, true)
}

func TestDatapathFifthSDFFilterIsSelectable(t *testing.T) {
	b := loadDatapath(t)
	filters := make([]SdfFilter, 5)
	for i := range filters {
		filters[i] = anyDatapathFilter(6)
	}
	filters[4] = anyDatapathFilter(17)
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true, SdfFilter: filters}); err != nil {
		t.Fatal(err)
	}
	action, _ := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false))
	if action == 1 {
		t.Fatal("fifth SDF Filter did not match")
	}
}

func TestDatapathUnfilteredSelectionKeepsConstraints(t *testing.T) {
	b := loadDatapath(t)
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	p := PdrInfo{PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true}
	for _, test := range []struct {
		name   string
		change func(*PdrInfo)
		drop   bool
	}{
		{"unconstrained", func(*PdrInfo) {}, false},
		{"source_interface", func(p *PdrInfo) { p.SourceInterfacePresent = true; p.SourceInterface = 1 }, true},
		{"ue_address", func(p *PdrInfo) { p.UEIPv4 = net.IP{203, 0, 113, 1} }, true},
		{"qfi", func(p *PdrInfo) { p.QFIs = []uint8{9} }, true},
		{"sdf", func(p *PdrInfo) { p.SdfFilter = []SdfFilter{anyDatapathFilter(6)} }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := p
			test.change(&candidate)
			if err := b.PutPdrUplink(10, candidate); err != nil {
				t.Fatal(err)
			}
			action, _ := runDatapath(t, b, packet)
			if (action == 1) != test.drop {
				t.Fatalf("action=%d wantDrop=%v", action, test.drop)
			}
		})
	}
}
