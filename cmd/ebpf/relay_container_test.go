//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

// TS 29.244 V20.1.0 clause 5.17.3: only a labelled EPS-to-5GS
// forwarding tunnel inserts a DL container. Ordinary N9/N4-u relays retain it.
func TestOrdinaryRelayPreservesGTPOptions(t *testing.T) {
	for _, destination := range []uint8{1, 3} {
		for _, marker := range []bool{false, true} {
			for _, optional := range []bool{false, true} {
				t.Run(fmt.Sprintf("interface_%d_marker_%t_options_%t", destination, marker, optional), func(t *testing.T) {
					b := loadDatapath(t)
					id, err := b.NewFar(FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), DestinationInterface: destination, DestinationInterfacePresent: true})
					if err != nil {
						t.Fatal(err)
					}
					putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 9, QfiPresent: 1})
					if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, SourceInterfacePresent: true, SourceInterface: 0, FarId: id, QerIDs: []uint32{1}, OuterHeaderRemovalPresent: true, NRFlag: true}); err != nil {
						t.Fatal(err)
					}
					flags := byte(0x30)
					var options []byte
					if optional {
						flags = 0x34
						options = []byte{0, 0, 0, 0x20, 1, 0xab, 0xcd, 0}
					}
					input := gtpDatapath(t, udpDatapath(t, false), options, flags, false)
					if marker {
						g := append([]byte{flags, 254, 0, 0, 0, 0, 0, 10}, options...)
						binary.BigEndian.PutUint16(g[2:4], uint16(len(g)-8))
						input = outerDatapath(t, g, false)
					}
					action, output := runDatapath(t, b, input)
					if action != 4 {
						t.Fatalf("action=%d", action)
					}
					// TEID and outer addresses change. Flags, extension chain and payload do not.
					if output[42] != input[42] || !bytes.Equal(output[50:], input[50:]) {
						t.Fatal("ordinary relay changed GTP options or payload")
					}
				})
			}
		}
	}
}
