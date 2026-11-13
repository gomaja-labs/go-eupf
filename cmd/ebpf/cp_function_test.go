//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
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
	extension := gtpu.GTPExtensionHeaders[0]
	if extension.Type != 0x85 || len(extension.Content) < 2 || extension.Content[1]&0x3f != 9 {
		t.Fatalf("wrong CP downlink QFI: %+v", extension)
	}
	var counters IpEntrypointUrrInfo
	if err := b.UrrMap.Lookup(uint32(1), &counters); err != nil {
		t.Fatal(err)
	}
	if counters.Ul != 0 || counters.Dl == 0 {
		t.Fatalf("CP downlink charged in wrong direction: %+v", counters)
	}
}

func TestDatapathCPFunctionToDNUsesUplink(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{DlGateStatus: 1})
	id, err := b.NewFar(FarInfo{Action: 2, DestinationInterface: 1, DestinationInterfacePresent: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, SourceInterfacePresent: true, SourceInterface: 3, FarId: id, QerIDs: []uint32{1}, UrrIDs: []uint32{1}, OuterHeaderRemovalPresent: true}); err != nil {
		t.Fatal(err)
	}
	action, out := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false))
	if action != 2 {
		t.Fatalf("CP-to-DN must use open UL gate and strip GTP-U: %d", action)
	}
	if gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default).Layer(layers.LayerTypeGTPv1U) != nil {
		t.Fatal("CP-to-DN kept outer tunnel")
	}
	var usage IpEntrypointUrrInfo
	if err := b.UrrMap.Lookup(uint32(1), &usage); err != nil {
		t.Fatal(err)
	}
	if usage.Ul == 0 || usage.Dl != 0 {
		t.Fatalf("CP-to-DN charged the wrong direction: %+v", usage)
	}
}

func TestDatapathCPFunctionDirections(t *testing.T) {
	for _, row := range []struct {
		name                string
		source, destination uint8
		uplink, native      bool
	}{
		{"UE-to-CP", 0, 3, true, false}, {"CP-to-UE", 3, 0, false, false}, {"CP-to-DN-Core", 3, 1, true, false}, {"CP-to-DN-N6", 3, 2, true, false}, {"DN-to-CP", 1, 3, false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			b := loadDatapath(t)
			far := FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), DestinationInterface: row.destination, DestinationInterfacePresent: true}
			if row.source == 3 && row.uplink {
				far.OuterHeaderCreation, far.Teid, far.RemoteIP = 0, 0, 0
			}
			id, err := b.NewFar(far)
			if err != nil {
				t.Fatal(err)
			}
			qer := IpEntrypointQerInfo{Qfi: 9, QfiPresent: 1, Dscp: 32}
			if row.uplink {
				qer.DlGateStatus = 1
			} else {
				qer.UlGateStatus = 1
			}
			putDatapath(t, b.QerMap.Put, uint32(1), &qer)
			pdr := PdrInfo{PdrID: 1, SourceInterfacePresent: true, SourceInterface: row.source, FarId: id, QerIDs: []uint32{1}, UrrIDs: []uint32{1}, OuterHeaderRemovalPresent: !row.native, NRFlag: true}
			packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
			if row.native {
				if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, pdr); err != nil {
					t.Fatal(err)
				}
				packet = ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false))
			} else if err := b.PutPdrUplink(10, pdr); err != nil {
				t.Fatal(err)
			}
			action, out := runDatapath(t, b, packet)
			expected := uint32(4)
			if row.source == 3 && row.uplink {
				expected = 2
			}
			if action != expected {
				t.Fatalf("wrong gate/direction: action=%d want=%d", action, expected)
			}
			decoded := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			if far.OuterHeaderCreation != 0 {
				tunnel, ok := decoded.Layer(layers.LayerTypeGTPv1U).(*layers.GTPv1U)
				if !ok || tunnel.TEID != 200 {
					t.Fatal("wrong CP tunnel")
				}
				ip4, _ := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if !ip4.SrcIP.Equal(net.IP{192, 0, 2, 1}) {
					t.Fatalf("wrong N4-u/N3 source: %s", ip4.SrcIP)
				}
				if ip4.TOS != 32 {
					t.Fatalf("CP tunnel discarded QoS marking: %d", ip4.TOS)
				}
			}
			var before IpEntrypointUrrInfo
			if err := b.UrrMap.Lookup(uint32(1), &before); err != nil {
				t.Fatal(err)
			}
			if row.uplink && (before.Ul != 32 || before.Dl != 0) || !row.uplink && (before.Dl != 32 || before.Ul != 0) {
				t.Fatalf("wrong usage direction: %+v", before)
			}
			if row.uplink {
				qer.UlGateStatus, qer.DlGateStatus = 1, 0
			} else {
				qer.UlGateStatus, qer.DlGateStatus = 0, 1
			}
			putDatapath(t, b.QerMap.Put, uint32(1), &qer)
			action, _ = runDatapath(t, b, packet)
			if action != 1 {
				t.Fatalf("closed directional gate did not drop: %d", action)
			}
			var after IpEntrypointUrrInfo
			if err := b.UrrMap.Lookup(uint32(1), &after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("closed gate charged usage")
			}
		})
	}
}
