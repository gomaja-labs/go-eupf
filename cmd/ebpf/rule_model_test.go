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
	if err := b.PutPdrUplink(10, PdrInfo{OuterHeaderRemovalPresent: true, PdrID: 1, FarId: 1, QerIDs: []uint32{1}, SdfFilter: []SdfFilter{anyDatapathFilter(3)}}); err != nil {
		t.Fatal(err)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	before, _ := runDatapath(t, b, packet)
	if before == 1 {
		t.Fatalf("first PDR did not forward before insertion: %d", before)
	}
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, FarId: 2, QerIDs: []uint32{1}, SdfFilter: []SdfFilter{anyDatapathFilter(2)}}); err != nil {
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
	first := PdrInfo{SessionID: 9, PdrID: 1, Precedence: 100, OuterHeaderRemovalPresent: true, FarId: 1, SdfFilter: []SdfFilter{anyDatapathFilter(3)}}
	second := PdrInfo{SessionID: 9, PdrID: 2, Precedence: 10, FarId: 2, UEIPv4: net.IP{192, 0, 2, 99}, SdfFilter: []SdfFilter{anyDatapathFilter(3)}}
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
	second.SdfFilter = []SdfFilter{anyDatapathFilter(2), anyDatapathFilter(3)}
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
