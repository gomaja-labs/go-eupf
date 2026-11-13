//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

func TestBufferRendererMatchesForwardingWithoutChargingUsageTwice(t *testing.T) {
	b := loadDatapath(t)
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	far := FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), TransportLevelMarking: 0xb8fc}
	if err := b.UpdateFar(3, far); err != nil {
		t.Fatal(err)
	}
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 9, QfiPresent: 1})
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) {
			if err := b.UpdateFar(3, far); err != nil {
				t.Fatal(err)
			}
			info := PdrInfo{SessionID: 42, PdrID: 9, FarId: 3, QerIDs: []uint32{1}, UrrIDs: []uint32{1}, NRFlag: true}
			put := func(info PdrInfo) {
				t.Helper()
				var err error
				if v6 {
					err = b.PutPdrDownlink(net.ParseIP("2001:db8::2"), info)
				} else {
					err = b.PutPdrDownlink(net.IP{198, 51, 100, 2}, info)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			put(info)
			typ := layers.EthernetTypeIPv4
			if v6 {
				typ = layers.EthernetTypeIPv6
			}
			packet := ethernetDatapath(t, typ, udpDatapath(t, v6))
			action, expected := runDatapath(t, b, packet)
			if action != 4 {
				t.Fatalf("ordinary forwarding action=%d", action)
			}
			buffered := far
			buffered.Action = 12
			buffered.BufferSessionID = 42
			buffered.BufferCookie = 7
			if err := b.UpdateFar(4, buffered); err != nil {
				t.Fatal(err)
			}
			info.FarId = 4
			put(info)
			before, err := b.GetUrr(1)
			if err != nil {
				t.Fatal(err)
			}
			if action, _ := runDatapath(t, b, packet); action != 1 {
				t.Fatalf("buffer action=%d", action)
			}
			reader.SetDeadline(time.Now().Add(time.Second))
			record, err := reader.Read()
			if err != nil {
				t.Fatal(err)
			}
			admitted, err := b.GetUrr(1)
			if err != nil || admitted.DownlinkVolume <= before.DownlinkVolume {
				t.Fatal("admission did not account the packet")
			}
			forwarding := far
			forwarding.BufferSessionID, forwarding.BufferCookie = record.SessionID, record.Cookie
			if err := b.UpdateFar(3, forwarding); err != nil {
				t.Fatal(err)
			}
			rendered, err := b.RenderBufferedPacket(record, 3)
			if err != nil {
				t.Fatal(err)
			}
			if rendered.Action != 4 || rendered.Ifindex == 0 || !bytes.Equal(rendered.Frame, expected) {
				t.Fatalf("rendering differs: action=%d interface=%d bytes_equal=%t", rendered.Action, rendered.Ifindex, bytes.Equal(rendered.Frame, expected))
			}
			after, err := b.GetUrr(1)
			if err != nil || after != admitted {
				t.Fatalf("rendering charged usage again: before=%+v after=%+v error=%v", admitted, after, err)
			}
		})
	}
}
