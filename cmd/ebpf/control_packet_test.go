//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestUnknownTunnelErrorIndication(t *testing.T) {
	b := loadDatapath(t)
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	action, out := runDatapath(t, b, packet)
	offset := 14 + 20 + 8
	if action != 3 || len(out) < offset+24 {
		t.Fatalf("unknown TEID did not produce Error Indication: action=%d length=%d", action, len(out))
	}
	g := out[offset:]
	if g[1] != 26 || binary.BigEndian.Uint32(g[4:8]) != 0 || binary.BigEndian.Uint16(g[2:4]) != 16 {
		t.Fatal("wrong Error Indication envelope")
	}
	if g[12] != 16 || binary.BigEndian.Uint32(g[13:17]) != 10 || g[17] != 133 || binary.BigEndian.Uint16(g[18:20]) != 4 || !net.IP(g[20:24]).Equal(net.IP{192, 0, 2, 1}) {
		t.Fatal("wrong Error Indication TEID/peer address")
	}
	var next uint64
	if err := b.GtpErrorBudget.Lookup(uint32(0), &next); err != nil {
		t.Fatal(err)
	}
	if next == 0 {
		t.Fatal("reply did not charge the diagnostic budget")
	}
	// Force the deterministic future-time boundary, independent of capture I/O.
	next = ^uint64(0)
	if err := b.GtpErrorBudget.Put(uint32(0), &next); err != nil {
		t.Fatal(err)
	}
	action, _ = runDatapath(t, b, packet)
	if action != 1 {
		t.Error("repeated Error Indication was not rate limited")
	}
}

func TestZeroTunnelDoesNotIndicateError(t *testing.T) {
	b := loadDatapath(t)
	g := make([]byte, 8)
	g[0] = 0x30
	g[1] = 255
	inner := udpDatapath(t, false)
	binary.BigEndian.PutUint16(g[2:4], uint16(len(inner)))
	g = append(g, inner...)
	action, _ := runDatapath(t, b, outerDatapath(t, g, false))
	if action != 1 {
		t.Errorf("zero TEID action=%d, want silent discard", action)
	}
}

func TestEndMarkerForwarding(t *testing.T) {
	for _, known := range []bool{true, false} {
		t.Run(map[bool]string{true: "known", false: "unknown"}[known], func(t *testing.T) {
			b := loadDatapath(t)
			putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
			g := make([]byte, 8)
			g[0] = 0x30
			g[1] = 254
			binary.BigEndian.PutUint32(g[4:8], 10)
			if !known {
				if err := b.DeletePdrUplink(10, 0, 1); err != nil {
					t.Fatal(err)
				}
			}
			action, out := runDatapath(t, b, outerDatapath(t, g, false))
			if known {
				if action != 4 || len(out) < 50 || out[43] != 254 || binary.BigEndian.Uint32(out[46:50]) != 20 {
					t.Errorf("End Marker not forwarded: action=%d", action)
				}
			} else if action != 1 {
				t.Errorf("unknown End Marker action=%d", action)
			}
			usage, err := b.GetUrr(1)
			if err != nil {
				t.Fatal(err)
			}
			if usage.UplinkVolume != 0 || usage.DownlinkVolume != 0 {
				t.Error("End Marker charged as user data")
			}
		})
	}
}

func TestUnknownRequiredExtensionNotification(t *testing.T) {
	b := loadDatapath(t)
	packet := gtpDatapath(t, udpDatapath(t, false), []byte{0, 0, 0, 0xe0, 1, 0, 0, 0}, 0x34, false)
	action, out := runDatapath(t, b, packet)
	offset := 14 + 20 + 8
	if action != 3 || len(out) < offset+16 {
		t.Fatalf("missing supported-extension notification: action=%d", action)
	}
	g := out[offset:]
	if g[1] != 31 || g[12] != 141 || g[13] != 0 || g[14] != 1 || g[15] != 0x85 {
		t.Fatal("wrong supported extension list")
	}
	usage, err := b.GetUrr(1)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UplinkVolume != 0 {
		t.Error("unsupported extension charged as user data")
	}
}

func TestIntermediateUnknownExtensionComprehension(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
	// TS 29.281 V19.2.0 figure 5.2.1-2: bits 10 require comprehension
	// only at the ultimate endpoint; an intermediate UPF forwards the header.
	packet := gtpDatapath(t, udpDatapath(t, false), []byte{0, 0, 0, 0xa0, 1, 0, 0, 0}, 0x34, false)
	action, out := runDatapath(t, b, packet)
	if action != 4 || len(out) < 58 || out[43] != 255 || out[53] != 0xa0 {
		t.Errorf("intermediate discarded endpoint-only extension: action=%d", action)
	}
}

func TestControlReplyDestinationPort(t *testing.T) {
	for _, kind := range []string{"echo", "error", "extension"} {
		t.Run(kind, func(t *testing.T) {
			b := loadDatapath(t)
			g := make([]byte, 8)
			g[0], g[1] = 0x30, 255
			binary.BigEndian.PutUint32(g[4:8], 10)
			want := uint16(2152)
			switch kind {
			case "echo":
				g[0], g[1] = 0x32, 1
				g = append(g, 0x12, 0x34, 0, 0)
				want = 43210
			case "error":
				if err := b.DeletePdrUplink(10, 0, 1); err != nil {
					t.Fatal(err)
				}
				g = append(g, udpDatapath(t, false)...)
			case "extension":
				g[0] = 0x34
				g = append(g, 0, 0, 0, 0xe0, 1, 0, 0, 0)
				g = append(g, udpDatapath(t, false)...)
			}
			binary.BigEndian.PutUint16(g[2:4], uint16(len(g)-8))
			action, out := runDatapath(t, b, outerDatapath(t, g, false, layers.UDPPort(43210)))
			if action != 3 || len(out) < 42 {
				t.Fatalf("no control response: action=%d", action)
			}
			if port := binary.BigEndian.Uint16(out[36:38]); port != want {
				t.Errorf("%s destination port=%d, want %d", kind, port, want)
			}
		})
	}
}
