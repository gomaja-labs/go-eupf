//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestDatapathProtocolNumbers(t *testing.T) {
	b := loadDatapath(t)
	for _, proto := range []uint16{0, 1, 6, 17, 47, 50, 58, 132, 253, 255} {
		t.Run(fmt.Sprint(proto), func(t *testing.T) {
			payload := make([]byte, 20)
			binary.BigEndian.PutUint16(payload, 1234)
			binary.BigEndian.PutUint16(payload[2:], 4321)
			if proto == 6 {
				payload[12] = 0x50
			}
			if proto == 17 {
				binary.BigEndian.PutUint16(payload[4:], uint16(len(payload)))
			}
			inner := serializeDatapath(t, &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocol(proto), SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 2}}, gopacket.Payload(payload))
			for _, match := range []bool{true, false} {
				f := anyDatapathFilter(proto)
				if !match {
					f.Protocol = (proto + 1) % 256
				}
				if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, Precedence: 10, FarId: 2, SdfFilter: []SdfFilter{f}}); err != nil {
					t.Fatal(err)
				}
				if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, Precedence: 20, FarId: 1, OuterHeaderRemovalPresent: true}); err != nil {
					t.Fatal(err)
				}
				action, _ := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false))
				if (action == 1) != match {
					t.Fatalf("protocol %d match=%t action=%d", proto, match, action)
				}
			}
		})
	}
}

func TestDatapathSCTPPorts(t *testing.T) {
	b := loadDatapath(t)
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload, 1234)
	binary.BigEndian.PutUint16(payload[2:], 4321)
	inner := serializeDatapath(t, &layers.IPv4{Version: 4, TTL: 64, Protocol: 132, SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 2}}, gopacket.Payload(payload))
	for _, port := range []uint16{4321, 4322} {
		f := anyDatapathFilter(132)
		f.PortsPresent = true
		f.DstPortRange = PortRange{port, port}
		if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, Precedence: 10, FarId: 2, SdfFilter: []SdfFilter{f}}); err != nil {
			t.Fatal(err)
		}
		if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, Precedence: 20, FarId: 1, OuterHeaderRemovalPresent: true}); err != nil {
			t.Fatal(err)
		}
		action, _ := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false))
		if (action == 1) != (port == 4321) {
			t.Fatalf("port %d action %d", port, action)
		}
	}
}
