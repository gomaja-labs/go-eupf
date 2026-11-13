//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestOutgoingTunnelPortIsStableAcrossIngressPaths(t *testing.T) {
	// TS 29.281 V19.2.0 clauses 4.4.2.0 and 4.4.2.6: choose a
	// stable per-tunnel dynamic source port, shared with generated End Markers.
	for _, native := range []bool{true, false} {
		t.Run(map[bool]string{true: "N6", false: "relay"}[native], func(t *testing.T) {
			b := loadDatapath(t)
			putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2})})
			packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
			packet = outerDatapath(t, packet[42:], false, 45678)
			if native {
				if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{FarId: 1}); err != nil {
					t.Fatal(err)
				}
				packet = ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false))
			}
			action, out := runDatapath(t, b, packet)
			if action != 4 {
				t.Fatalf("forwarding action=%d", action)
			}
			decoded := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			udp, ok := decoded.Layer(layers.LayerTypeUDP).(*layers.UDP)
			if !ok {
				t.Fatal("missing UDP tunnel header")
			}
			if udp.SrcPort != 49352 || udp.DstPort != 2152 {
				t.Fatalf("outgoing tunnel ports=%d to %d; want 49352 to 2152", udp.SrcPort, udp.DstPort)
			}
		})
	}
}
