//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// TS 29.281 V19.2.0 figure 5.2.1-2: an intermediate node must not
// forward an unknown extension whose comprehension bits are 01. Keep the
// intact packet on the same slow path used for G-PDUs until it can be removed.
func TestHandoverMarkerDoesNotRelayDiscardRequiredExtension(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 9, QfiPresent: 1})
	g := []byte{0x34, 254, 0, 8, 0, 0, 0, 10, 0, 0, 0, 0x41, 1, 0xab, 0xcd, 0}
	packet := outerDatapath(t, g, false)
	action, out := runDatapath(t, b, packet)
	if action != 2 {
		t.Fatalf("discard-required extension relayed: action=%d", action)
	}
	if !bytes.Equal(packet, out) {
		t.Fatal("slow-path marker changed before extension handling")
	}
}

// TS 29.281 V19.2.0 figure 5.2.1-2 and clause 5.2.1: every
// recipient must understand 11 extensions; markers do not solicit SEHN.
func TestHandoverMarkerDropsComprehensionRequiredExtension(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
	g := []byte{0x34, 254, 0, 8, 0, 0, 0, 10, 0, 0, 0, 0xc5, 1, 0xab, 0xcd, 0}
	before := (&UpfXdpActionStatistic{BpfObjects: b}).GetUpfExtStat()
	action, _ := runDatapath(t, b, outerDatapath(t, g, false))
	after := (&UpfXdpActionStatistic{BpfObjects: b}).GetUpfExtStat()
	if action != 1 {
		t.Fatalf("comprehension-required marker action=%d want drop", action)
	}
	if after.RxGtpUnexp != before.RxGtpUnexp+1 {
		t.Fatal("discarded marker was not counted")
	}
}

// TS 29.244 V20.1.0 clause 5.17.3; TS 38.415 V19.1.0 clause 5.5.2.1.
func TestHandoverMarkerInsertsMappedQFIWithoutChargingData(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 9, QfiPresent: 1, DlGateStatus: 1, UlGateStatus: 1, Rqi: 1})
	g := []byte{0x30, 254, 0, 0, 0, 0, 0, 10}
	action, out := runDatapath(t, b, outerDatapath(t, g, false))
	if action != 4 || len(out) < 58 {
		t.Fatalf("marker action=%d length=%d", action, len(out))
	}
	got := out[42:58]
	if got[0] != 0x34 || got[1] != 254 || binary.BigEndian.Uint16(got[2:4]) != 8 || binary.BigEndian.Uint32(got[4:8]) != 20 || got[11] != 0x85 || got[12] != 1 || got[13] != 0 || got[14] != 9 || got[15] != 0 {
		t.Fatal("marker lacks the mapped DL container or carries data-only RQI")
	}
	if !net.IP(out[26:30]).Equal(net.IP{192, 0, 2, 2}) || binary.BigEndian.Uint16(out[34:36]) != 49172 {
		t.Fatal("marker source differs from relayed G-PDUs")
	}
	usage, err := b.GetUrr(1)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UplinkVolume != 0 || usage.DownlinkVolume != 0 {
		t.Fatal("End Marker charged as user data")
	}
}

// An End Marker has no inner IP header: QFI mapping is selected without SDF
// parsing and must never fall through to an unrelated first E-RAB.
func TestHandoverMarkerSelectsMappedPDR(t *testing.T) {
	b := loadDatapath(t)
	for id := uint32(1); id <= 2; id++ {
		putDatapath(t, b.FarMap.Put, id, &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: id * 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
	}
	for id, qfi := range []uint8{7, 9} {
		if err := b.PutPdrUplink(10, PdrInfo{PdrID: uint32(id + 1), Precedence: uint32(id), FarId: uint32(id + 1), QFIs: []uint8{qfi}, OuterHeaderRemovalPresent: true}); err != nil {
			t.Fatal(err)
		}
	}
	// TS 29.281 V19.2.0 clauses 5.2.2.7 and 7.3.2.1: an ordinary
	// marker has no QFI and follows the first ingress-matching PDR.
	marker := []byte{0x30, 254, 0, 0, 0, 0, 0, 10}
	action, out := runDatapath(t, b, outerDatapath(t, marker, false))
	if action != 4 || binary.BigEndian.Uint32(out[46:50]) != 20 {
		t.Fatalf("container-less ordinary marker dropped or misrouted: action=%d", action)
	}
	for _, qfi := range []byte{7, 9, 11} {
		g := []byte{0x34, 254, 0, 8, 0, 0, 0, 10, 0, 0, 0, 0x85, 1, 0, qfi, 0}
		action, out := runDatapath(t, b, outerDatapath(t, g, false))
		if qfi == 11 {
			if action != 1 {
				t.Fatal("unmapped QFI forwarded")
			}
			continue
		}
		want := uint32(20)
		if qfi == 9 {
			want = 40
		}
		if action != 4 || binary.BigEndian.Uint32(out[46:50]) != want {
			t.Fatalf("QFI %d: action=%d TEID=%d want=%d", qfi, action, binary.BigEndian.Uint32(out[46:50]), want)
		}
	}
}

func TestHandoverMarkerDeletesOnlyTheContainer(t *testing.T) {
	for _, options := range []bool{false, true} {
		for _, sequence := range []bool{false, true} {
			t.Run(map[bool]string{false: "base", true: "IP_options"}[options]+map[bool]string{false: "_no_sequence", true: "_sequence"}[sequence], func(t *testing.T) {
				b := loadDatapath(t)
				putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
				if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true, GtpExtensionHeaderDeletion: 1, QFIs: []uint8{9}, UrrIDs: []uint32{1}}); err != nil {
					t.Fatal(err)
				}
				// A comprehension-not-required extension precedes PSC; the Private
				// Extension IE after it belongs to the End Marker, not the GTP chain.
				g := []byte{0x34, 254, 0, 0, 0, 0, 0, 10, 0x12, 0x34, 0, 0x20, 1, 0xab, 0xcd, 0x85, 1, 0, 9, 0, 255, 0, 3, 1, 2, 3}
				if sequence {
					g[0] |= 2
				}
				binary.BigEndian.PutUint16(g[2:4], uint16(len(g)-8))
				action, out := runDatapath(t, b, outerDatapath(t, g, options))
				offset := 42
				if options {
					offset += 4
				}
				if action != 4 || len(out) < offset+22 {
					t.Fatalf("marker action=%d length=%d", action, len(out))
				}
				got := out[offset : offset+22]
				if got[0] != g[0] || got[11] != 0x20 || got[12] != 1 || got[13] != 0xab || got[14] != 0xcd || got[15] != 0 || binary.BigEndian.Uint16(got[2:4]) != 14 || got[16] != 255 || got[21] != 3 {
					t.Fatal("container deletion damaged retained extension or signalling body")
				}
			})
		}
	}
}

func TestHandoverMarkerDropsTheEmptyOptionalWord(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true, GtpExtensionHeaderDeletion: 1}); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []bool{false, true} {
		g := []byte{0x34, 254, 0, 8, 0, 0, 0, 10, 0x12, 0x34, 0, 0x85, 1, 0, 9, 0}
		if sequence {
			g[0] |= 2
		}
		action, out := runDatapath(t, b, outerDatapath(t, g, false))
		if action != 4 {
			t.Fatal(action)
		}
		want := uint16(0)
		flags := byte(0x30)
		if sequence {
			want = 4
			flags = 0x32
		}
		if out[42] != flags || binary.BigEndian.Uint16(out[44:46]) != want {
			t.Fatal("empty optional word or E flag retained")
		}
		if sequence && binary.BigEndian.Uint16(out[50:52]) != 0x1234 {
			t.Fatal("sequence lost")
		}
	}
}

// The same PDR instruction applies to data preceding the marker.
func TestHandoverDataUsesTheSameContainerMapping(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "EPS_to_5GS", true: "5GS_to_EPS"}[remove], func(t *testing.T) {
			b := loadDatapath(t)
			putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{InsertHandoverContainer: 1, Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
			putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 9, QfiPresent: 1})
			pdr := PdrInfo{PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true, QerIDs: []uint32{1}, NRFlag: true}
			var optional []byte
			flags := byte(0x30)
			want := byte(0x34)
			if remove {
				pdr.GtpExtensionHeaderDeletion = 1
				optional = []byte{0, 0, 0, 0x85, 1, 0, 9, 0}
				flags = 0x34
				want = 0x30
			}
			if err := b.PutPdrUplink(10, pdr); err != nil {
				t.Fatal(err)
			}
			action, out := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), optional, flags, false))
			if action != 4 || out[42] != want {
				t.Fatalf("data container mapping action=%d flags=%x want=%x", action, out[42], want)
			}
			offset := 50
			if !remove {
				offset = 58
				if out[56] != 9 {
					t.Fatal("mapped QFI lost")
				}
			}
			if out[offset]>>4 != 4 {
				t.Fatal("inner IP packet damaged")
			}
		})
	}
}

func TestHandoverMarkerNeverLeavesN19(t *testing.T) {
	b := loadDatapath(t)
	if err := b.UpdateFar(1, FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 20, RemoteIP: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3}), EndMarkerSuppressed: true}); err != nil {
		t.Fatal(err)
	}
	action, _ := runDatapath(t, b, outerDatapath(t, []byte{0x30, 254, 0, 0, 0, 0, 0, 10}, false))
	if action != 1 {
		t.Fatal("End Marker sent over N19")
	}
}
