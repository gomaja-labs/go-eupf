package core

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/utils"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestPFCPTraceBoundAndWildcardFamilies(t *testing.T) {
	for _, tc := range []struct{ name, bind, peer string }{
		{"IPv4", "127.0.0.1:0", "127.0.0.1:0"},
		{"IPv6", "[::1]:0", "[::1]:0"},
		{"wildcard_IPv4", "[::]:0", "127.0.0.1:0"},
		{"wildcard_IPv6", "[::]:0", "[::1]:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			config.Conf.TraceHeartbeat = true
			bind, err := net.ResolveUDPAddr("udp", tc.bind)
			if err != nil {
				t.Fatal(err)
			}
			socket, err := net.ListenUDP("udp", bind)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.udpConn.Close(); err != nil {
				t.Fatal(err)
			}
			conn.udpConn = socket
			conn.nodeAddrV4 = socket.LocalAddr().(*net.UDPAddr).AddrPort()
			directory := t.TempDir()
			dumper, err := utils.NewPacketDumper(directory, 1, 1<<20, 100)
			if err != nil {
				t.Fatal(err)
			}
			conn.dumper = dumper
			conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeHeartbeatRequest: func(_ *PfcpConnection, request message.Message, _ string) (message.Message, bool, error) {
				return message.NewHeartbeatResponse(request.Sequence(), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))), true, nil
			}}
			peerAddr, err := net.ResolveUDPAddr("udp", tc.peer)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := net.ListenUDP("udp", peerAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			destination := *socket.LocalAddr().(*net.UDPAddr)
			if destination.IP.IsUnspecified() {
				destination.IP = peerAddr.IP
			}
			request := protocolWire(t, message.NewHeartbeatRequest(10, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))))
			if _, err = peer.WriteToUDP(request, &destination); err != nil {
				t.Fatal(err)
			}
			if err = socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 2048)
			n, remote, err := socket.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			conn.handleDatagram(buffer[:n], remote, socket.LocalAddr().(*net.UDPAddr).AddrPort())
			_ = identityRead(t, peer)
			dumper.Close(false)
			if dumper.GetPacketsWritten() != 2 {
				t.Fatalf("records=%d", dumper.GetPacketsWritten())
			}
			data, err := os.ReadFile(filepath.Join(directory, "trace.pcap"))
			if err != nil {
				t.Fatal(err)
			}
			if output := os.Getenv("TRACE_CAPTURE_DIR"); output != "" {
				if err := os.WriteFile(filepath.Join(output, tc.name+".pcapng"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			file, err := os.Open(filepath.Join(directory, "trace.pcap"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			reader, err := pcapgo.NewNgReader(file, pcapgo.NgReaderOptions{WantMixedLinkType: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, incoming := range []bool{true, false} {
				raw, _, err := reader.ReadPacketData()
				if err != nil {
					t.Fatal(err)
				}
				family := layers.LayerTypeIPv4
				if peerAddr.IP.To4() == nil {
					family = layers.LayerTypeIPv6
				}
				packet := gopacket.NewPacket(raw, family, gopacket.Default)
				if packet.NetworkLayer() == nil {
					t.Fatalf("invalid network record: %v", packet.ErrorLayer())
				}
				local := conn.nodeAddrV4.Addr().Unmap()
				remoteIP := peer.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
				if local.IsUnspecified() {
					local = netip.IPv6Unspecified()
					if remoteIP.Is4() {
						local = netip.IPv4Unspecified()
					}
				}
				source, dest := remoteIP, local
				if !incoming {
					source, dest = dest, source
				}
				flow := packet.NetworkLayer().NetworkFlow()
				if flow.Src().String() != source.String() || flow.Dst().String() != dest.String() {
					t.Fatalf("unexpected endpoints: %s", flow)
				}
			}
		})
	}
}
