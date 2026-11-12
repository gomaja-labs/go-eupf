//go:build linux

package ebpf

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestDatapathCPFunctionDownlinkTunnel(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{UlGateStatus: 1, QfiPresent: 1, Qfi: 9})
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, SourceInterfacePresent: true, SourceInterface: 3, FarId: 3, QerIDs: []uint32{1}, UrrIDs: []uint32{1}, OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 6, NRFlag: true}); err != nil {
		t.Fatal(err)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	action, out := runDatapath(t, b, packet)
	if action != 4 {
		t.Fatalf("CP-originated downlink uses DL gate: action=%d", action)
	}
	decoded := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	gtpu, ok := decoded.Layer(layers.LayerTypeGTPv1U).(*layers.GTPv1U)
	if !ok || gtpu.TEID != 200 || len(gtpu.GTPExtensionHeaders) == 0 {
		t.Fatal("CP packet lacks the assigned N3 tunnel/QFI")
	}
	var counters IpEntrypointUrrInfo
	if err := b.UrrMap.Lookup(uint32(1), &counters); err != nil {
		t.Fatal(err)
	}
	if counters.Ul != 0 || counters.Dl == 0 {
		t.Fatalf("CP downlink charged in wrong direction: %+v", counters)
	}
}
