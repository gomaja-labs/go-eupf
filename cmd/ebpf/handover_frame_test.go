//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// decodeHandoverFrame decodes the returned frame and checks every outer length and
// checksum independently of the program's own arithmetic.
func decodeHandoverFrame(t *testing.T, out []byte) (*layers.IPv4, *layers.UDP, []byte) {
	t.Helper()
	p := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	ipl, _ := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipl == nil {
		t.Fatalf("no IPv4 layer: %v", p.ErrorLayer())
	}
	hdr := out[14 : 14+int(ipl.IHL)*4]
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if sum != 0xffff {
		t.Fatalf("IPv4 header checksum invalid: folded sum %#x", sum)
	}
	udpStart := 14 + int(ipl.IHL)*4
	udp := out[udpStart:]
	ul := int(binary.BigEndian.Uint16(udp[4:6]))
	if int(ipl.Length) != int(ipl.IHL)*4+ul {
		t.Fatalf("IPv4 total length %d != IHL %d + UDP length %d", ipl.Length, int(ipl.IHL)*4, ul)
	}
	g := udp[8:ul]
	if int(binary.BigEndian.Uint16(g[2:4]))+8 != len(g) {
		t.Fatalf("GTP length %d != UDP payload %d - 8", binary.BigEndian.Uint16(g[2:4]), len(g))
	}
	u := &layers.UDP{}
	if err := u.DecodeFromBytes(udp[:ul], gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	return ipl, u, g
}

// Wire check of the inserted container after every rewrite, IPv4 options,
// optional sequence field and a preceding comprehension-not-required header.
func TestHandoverInsertedContainerLengthsAndChecksums(t *testing.T) {
	for _, options := range []bool{false, true} {
		for _, flags := range []byte{0x30, 0x32, 0x34} {
			b := loadDatapath(t)
			putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
			putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 9, QfiPresent: 1})
			g := []byte{flags, 254, 0, 0, 0, 0, 0, 10}
			if flags&0x06 != 0 {
				g = append(g, 0x12, 0x34, 0, 0)
				if flags&0x04 != 0 {
					g[11] = 0x20 // 00-type header follows
					g = append(g, 1, 0xab, 0xcd, 0)
				}
			}
			g = append(g, 255, 0, 2, 7, 8) // Private Extension body
			binary.BigEndian.PutUint16(g[2:4], uint16(len(g)-8))
			action, out := runDatapath(t, b, outerDatapath(t, g, options))
			if action != 4 {
				t.Fatalf("options=%t flags=%#x action=%d", options, flags, action)
			}
			ipl, u, gtp := decodeHandoverFrame(t, out)
			if !ipl.SrcIP.Equal(net.IP{192, 0, 2, 2}) || !ipl.DstIP.Equal(net.IP{192, 0, 2, 3}) || u.SrcPort != 49152|20 || u.DstPort != 2152 || u.Checksum != 0 {
				t.Fatalf("outer src=%s dst=%s sport=%d dport=%d csum=%#x", ipl.SrcIP, ipl.DstIP, u.SrcPort, u.DstPort, u.Checksum)
			}
			if gtp[0]&0x04 == 0 || gtp[11] != 0x85 || gtp[12] != 1 || gtp[13] != 0 || gtp[14] != 9 {
				t.Fatalf("options=%t flags=%#x container changed", options, flags)
			}
			if flags&0x02 != 0 && binary.BigEndian.Uint16(gtp[8:10]) != 0x1234 {
				t.Fatal("sequence number lost")
			}
			want := byte(0)
			if flags&0x04 != 0 {
				want = 0x20
			}
			if gtp[15] != want {
				t.Fatalf("container next type %#x want %#x", gtp[15], want)
			}
			tail := gtp[len(gtp)-5:]
			if tail[0] != 255 || tail[3] != 7 || tail[4] != 8 {
				t.Fatal("signalling body damaged")
			}
		}
	}
}

// Deleting the last of two extension headers on a G-PDU keeps E=1 and
// terminates the remaining chain.
func TestHandoverDeleteTrailingContainerFromData(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true, GtpExtensionHeaderDeletion: 1, QerIDs: []uint32{1}, UrrIDs: []uint32{1}}); err != nil {
		t.Fatal(err)
	}
	optional := []byte{0, 0, 0, 0x20, 1, 0xab, 0xcd, 0x85, 1, 0, 9, 0}
	action, out := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), optional, 0x34, true))
	if action != 4 {
		t.Fatalf("action=%d", action)
	}
	_, _, gtp := decodeHandoverFrame(t, out)
	if gtp[0] != 0x34 || gtp[11] != 0x20 || gtp[15] != 0 || gtp[16]>>4 != 4 {
		t.Fatal("chain after deletion damaged")
	}
}

func runHandoverDatapath(t *testing.T, b *BpfObjects, input []byte) (uint32, []byte) {
	t.Helper()
	action, output := runDatapath(t, b, input)
	if action == 3 || action == 4 {
		decodeHandoverFrame(t, output)
	}
	return action, output
}
