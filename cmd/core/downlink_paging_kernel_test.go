//go:build linux

package core

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestApplicationBufferPagingPolicyDSCP(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("IPv6=%t", v6), func(t *testing.T) {
			plane, _, conn, _, session, peer := publishPacketBufferFixtureOptions(t, BufferingOptions{Packets: 8, PerSession: 8, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
			if v6 {
				conn.stateMu.Lock()
				pdr := session.PDRs[9]
				pdr.Ipv6 = net.ParseIP("2001:db8::2")
				session.PDRs[9] = pdr
				err := applyPDR(pdr, conn.mapOperations)
				conn.stateMu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			go conn.Run()
			for _, dscp := range []uint8{0, 7, 8, 63} {
				// Set ECN too, so copying the entire traffic-class octet fails.
				udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
				var ip gopacket.SerializableLayer
				if v6 {
					header := &layers.IPv6{Version: 6, TrafficClass: dscp<<2 | 3, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
					ip = header
					if err := udp.SetNetworkLayerForChecksum(header); err != nil {
						t.Fatal(err)
					}
				} else {
					header := &layers.IPv4{Version: 4, TOS: dscp<<2 | 3, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 2}}
					ip = header
					if err := udp.SetNetworkLayerForChecksum(header); err != nil {
						t.Fatal(err)
					}
				}
				ether := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
				if v6 {
					ether.EthernetType = layers.EthernetTypeIPv6
				}
				buffer := gopacket.NewSerializeBuffer()
				if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ether, ip, udp, gopacket.Payload([]byte{1, 2, 3, 4})); err != nil {
					t.Fatal(err)
				}
				action, _, err := plane.UpfIpEntrypointFunc.Test(buffer.Bytes())
				if err != nil || action != 1 {
					t.Fatalf("buffer action=%d error=%v", action, err)
				}
				report := identityRead(t, peer).(*message.SessionReportRequest)
				fields, err := report.DownlinkDataReport.DownlinkDataReport()
				if err != nil || len(fields.DownlinkDataServiceInformation) != 1 {
					t.Fatalf("missing service information: %v", err)
				}
				info, err := fields.DownlinkDataServiceInformation[0].DownlinkDataServiceInformation()
				if err != nil || info.Flags&1 == 0 || info.PagingPolicyIndication != dscp {
					t.Fatalf("IPv6=%t DSCP=%d service=%+v error=%v", v6, dscp, info, err)
				}
				t.Logf("IPv6=%t DSCP=%d report-sequence=%d", v6, dscp, report.Sequence())
				conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseSystemFailure))), peer.LocalAddr().(*net.UDPAddr))
			}
		})
	}
}
