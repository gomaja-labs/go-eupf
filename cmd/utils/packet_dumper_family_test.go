package utils

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestPacketDumperSignallingAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		name, local, peer string
		version           byte
	}{
		{"IPv4", "192.0.2.1:8805", "192.0.2.2:8805", 4},
		{"IPv4-mapped", "[::ffff:192.0.2.1]:8805", "[::ffff:192.0.2.2]:8805", 4},
		{"IPv6", "[2001:db8::1]:8805", "[2001:db8::2]:8805", 6},
		{"IPv4-wildcard", "0.0.0.0:8805", "192.0.2.2:8805", 4},
		{"IPv6-wildcard", "[::]:8805", "[2001:db8::2]:8805", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			dumper, err := NewPacketDumper(directory, 1, 1<<20, 100)
			if err != nil {
				t.Fatal(err)
			}
			local, peer := netip.MustParseAddrPort(tc.local), netip.MustParseAddrPort(tc.peer)
			payload := []byte{0x20, 1, 0, 4, 0, 0, 1, 0}
			dumper.DumpRawIn(peer, local, payload)
			dumper.DumpRawOut(peer, local, payload)
			dumper.Close(false)
			if got := dumper.GetPacketsWritten(); got != 2 {
				t.Fatalf("captured=%d want=2", got)
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
				kind := layers.LayerTypeIPv4
				if tc.version == 6 {
					kind = layers.LayerTypeIPv6
				}
				packet := gopacket.NewPacket(raw, kind, gopacket.Default)
				if packet.ErrorLayer() != nil {
					t.Fatal(packet.ErrorLayer().Error())
				}
				source, destination := peer.Addr().Unmap(), local.Addr().Unmap()
				if !incoming {
					source, destination = destination, source
				}
				flow := packet.NetworkLayer().NetworkFlow()
				if raw[0]>>4 != tc.version || flow.Src().String() != source.String() || flow.Dst().String() != destination.String() {
					t.Fatalf("record changed its address family or endpoints: %s", flow)
				}
				udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
				if !ok || !bytes.Equal(udp.Payload, payload) {
					t.Fatal("capture lost UDP payload")
				}
			}
		})
	}
}
