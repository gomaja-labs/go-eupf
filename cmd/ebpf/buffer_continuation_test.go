//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gopacket/gopacket"

	cilium "github.com/cilium/ebpf"
	"github.com/gopacket/gopacket/layers"
)

// These cases use small runtime map capacities; the complete verifier and
// forwarding programs are identical to the default-capacity fixtures.
func loadBufferContinuationDatapath(t *testing.T) *BpfObjects {
	t.Helper()
	return loadDatapath(t, func(b *BpfObjects) {
		b.SetPdrMapSize(64)
		b.SetFarMapSize(64)
		b.SetQerMapSize(64)
		b.SetUrrMapSize(64)
		b.SetBufferCapacity(64, 64)
	})
}

func TestBufferLocalTunnelContinuesWithoutRepeatingTheFirstLeg(t *testing.T) {
	b := loadBufferContinuationDatapath(t)
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	ip("route", "add", "198.51.100.0/24", "dev", "test-egress")
	ip("neigh", "add", "198.51.100.2", "lladdr", "02:00:00:00:00:02", "nud", "permanent", "dev", "test-egress")
	ip("-6", "route", "add", "2001:db8::/64", "dev", "test-egress")
	ip("-6", "neigh", "add", "2001:db8::2", "lladdr", "02:00:00:00:00:02", "nud", "permanent", "dev", "test-egress")
	t.Cleanup(func() {
		for _, args := range [][]string{{"-6", "neigh", "del", "2001:db8::2", "dev", "test-egress"}, {"-6", "route", "del", "2001:db8::/64"}, {"neigh", "del", "198.51.100.2", "dev", "test-egress"}, {"route", "del", "198.51.100.0/24"}} {
			if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
				t.Errorf("remove local route %v: %v %s", args, err, out)
			}
		}
	})

	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) {
			far := FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 10, RemoteIP: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 1})}
			if err := b.UpdateFar(3, far); err != nil {
				t.Fatal(err)
			}
			info := PdrInfo{SessionID: 42, PdrID: 9, FarId: 3, QerIDs: []uint32{1}, UrrIDs: []uint32{1}, NRFlag: true}
			put := func() {
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
			put()
			kind := layers.EthernetTypeIPv4
			if v6 {
				kind = layers.EthernetTypeIPv6
			}
			packet := ethernetDatapath(t, kind, udpDatapath(t, v6))
			action, want := runDatapath(t, b, packet)
			if action != 4 {
				t.Fatalf("ordinary local continuation=%d", action)
			}
			putDatapath(t, b.UrrMap.Put, uint32(1), &IpEntrypointUrrInfo{})
			buffered := far
			buffered.Action = 12
			buffered.BufferSessionID = 42
			buffered.BufferCookie = 7
			if err := b.UpdateFar(4, buffered); err != nil {
				t.Fatal(err)
			}
			info.FarId = 4
			put()
			if action, _ := runDatapath(t, b, packet); action != 1 {
				t.Fatalf("admission=%d", action)
			}
			reader.SetDeadline(time.Now().Add(time.Second))
			record, err := reader.Read()
			if err != nil {
				t.Fatal(err)
			}
			before, err := b.GetUrr(1)
			if err != nil || before.UplinkVolume != 0 {
				t.Fatalf("admission usage: %+v %v", before, err)
			}
			far.BufferSessionID, far.BufferCookie = 42, 7
			if err := b.UpdateFar(3, far); err != nil {
				t.Fatal(err)
			}
			rendered, err := b.RenderBufferedPacket(record, 3)
			if err != nil {
				t.Fatal(err)
			}
			if rendered.Action != 4 || rendered.Ifindex == 0 || !bytes.Equal(rendered.Frame, want) {
				t.Fatalf("local tunnel did not complete: action=%d interface=%d equal=%t", rendered.Action, rendered.Ifindex, bytes.Equal(rendered.Frame, want))
			}
			after, err := b.GetUrr(1)
			if err != nil || after.DownlinkVolume != before.DownlinkVolume || after.UplinkVolume != before.DownlinkVolume {
				t.Fatalf("initial leg was repeated or new leg uncharged: before=%+v after=%+v error=%v", before, after, err)
			}
			// A retry may follow a successful rendering, and the kernel's
			// test-run syscall may itself repeat after interruption.
			replay, err := b.RenderBufferedPacket(record, 3)
			if err != nil || !bytes.Equal(replay.Frame, rendered.Frame) {
				t.Fatalf("cached retry: %v", err)
			}
			data := bufferRenderInput(record, 3)
			context := struct{ Data, DataEnd, DataMeta, IngressIfindex, RxQueueIndex, EgressIfindex uint32 }{DataEnd: uint32(len(data)), IngressIfindex: record.IngressIfindex}
			if _, err = b.renderCollection.Programs["upf_buffer_render_func"].Run(&cilium.RunOptions{Data: data, Context: &context, Repeat: 2}); err != nil {
				t.Fatal(err)
			}
			repeated, err := b.GetUrr(1)
			if err != nil || repeated != after {
				t.Fatalf("retry repeated accounting: before=%+v after=%+v error=%v", after, repeated, err)
			}
			if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Sequence: record.Sequence, Downlink: true}); err != nil {
				t.Fatal(err)
			}
			var cached renderResult
			if err := b.renderCollection.Maps["buffer_rendered"].Lookup(renderKey{SessionID: 42, Cookie: 7, Sequence: record.Sequence}, &cached); !errors.Is(err, cilium.ErrKeyNotExist) {
				t.Fatalf("completed render retained: %v", err)
			}
		})
	}
}

func TestBufferRendererRetainsTransmitAction(t *testing.T) {
	b := loadBufferContinuationDatapath(t)
	iface, err := net.InterfaceByName("test-egress")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	info := PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, info); err != nil {
		t.Fatal(err)
	}
	packet := bufferedFrame(t, 2, 100)
	run := func() (uint32, []byte) {
		t.Helper()
		ctx := struct{ Data, DataEnd, DataMeta, IngressIfindex, RxQueueIndex, EgressIfindex uint32 }{DataEnd: uint32(len(packet)), IngressIfindex: uint32(iface.Index)}
		options := cilium.RunOptions{Data: packet, DataOut: make([]byte, len(packet)+512), Context: &ctx}
		a, e := b.UpfIpEntrypointFunc.Run(&options)
		if e != nil {
			t.Fatal(e)
		}
		return a, options.DataOut
	}
	action, want := run()
	if action != 3 {
		t.Fatalf("ordinary same-device action=%d", action)
	}
	far, err := b.GetFar(3)
	if err != nil {
		t.Fatal(err)
	}
	far.Action = 12
	far.BufferSessionID = 42
	far.BufferCookie = 7
	if err := b.UpdateFar(4, far); err != nil {
		t.Fatal(err)
	}
	info.FarId = 4
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, info); err != nil {
		t.Fatal(err)
	}
	if action, _ := run(); action != 1 {
		t.Fatalf("admission=%d", action)
	}
	reader.SetDeadline(time.Now().Add(time.Second))
	record, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	far.Action = 2
	if err := b.UpdateFar(3, far); err != nil {
		t.Fatal(err)
	}
	result, err := b.RenderBufferedPacket(record, 3)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != 3 || result.Ifindex != uint32(iface.Index) || !bytes.Equal(result.Frame, want) {
		t.Fatalf("TX changed: action=%d interface=%d equal=%t", result.Action, result.Ifindex, bytes.Equal(result.Frame, want))
	}
}

func TestBufferControlRepliesContinueAfterDeferredForwarding(t *testing.T) {
	b := loadBufferContinuationDatapath(t)
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"router solicitation", "invalid router solicitation", "echo"} {
		t.Run(kind, func(t *testing.T) {
			if err := b.UpdateFar(1, FarInfo{Action: 2}); err != nil {
				t.Fatal(err)
			}
			info := PdrInfo{SessionID: 42, PdrID: 1, FarId: 1, QerIDs: []uint32{1}, UrrIDs: []uint32{1}, OuterHeaderRemovalPresent: true, ReturnFarID: 3, ReturnQerIDs: []uint32{1}, ReturnNR: true}
			if err := b.PutPdrUplink(10, info); err != nil {
				t.Fatal(err)
			}
			var inner []byte
			if kind == "echo" {
				ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{192, 0, 2, 1}}
				inner = serializeDatapath(t, ip, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 5, Seq: 1})
				if err := b.PutPdrDownlink(net.IP{198, 51, 100, 1}, PdrInfo{FarId: 3, QerIDs: []uint32{1}}); err != nil {
					t.Fatal(err)
				}
			} else {
				code := uint8(0)
				if kind == "invalid router solicitation" {
					code = 1
				}
				inner = rsDatapath(t, "fe80::1234", 255, code)
			}
			packet := gtpDatapath(t, inner, nil, 0x30, false)
			action, want := runDatapath(t, b, packet)
			if action != 4 && action != 1 {
				t.Fatalf("ordinary reply action=%d", action)
			}
			if err := b.UpdateFar(4, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7}); err != nil {
				t.Fatal(err)
			}
			info.FarId = 4
			if err := b.PutPdrUplink(10, info); err != nil {
				t.Fatal(err)
			}
			if got, _ := runDatapath(t, b, packet); got != 1 {
				t.Fatalf("buffer action=%d", got)
			}
			reader.SetDeadline(time.Now().Add(time.Second))
			record, err := reader.Read()
			if err != nil {
				t.Fatal(err)
			}
			if err := b.UpdateFar(1, FarInfo{Action: 2, BufferSessionID: 42, BufferCookie: 7}); err != nil {
				t.Fatal(err)
			}
			before, err := b.GetUrr(1)
			if err != nil {
				t.Fatal(err)
			}
			got, err := b.RenderBufferedPacket(record, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != action || action == 4 && !bytes.Equal(got.Frame, want) {
				t.Fatalf("reply changed: action=%d want=%d bytes_equal=%t", got.Action, action, bytes.Equal(got.Frame, want))
			}
			after, err := b.GetUrr(1)
			if err != nil || before != after {
				t.Fatalf("reply repeated original accounting: %+v %+v %v", before, after, err)
			}
			if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Sequence: record.Sequence, Downlink: record.Downlink}); err != nil {
				t.Fatal(err)
			}

		})
	}
}

func TestBufferRendererPreservesRouteFallbacks(t *testing.T) {
	b := loadBufferContinuationDatapath(t)
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}

	for _, outcome := range []string{"unresolved neighbour", "FIB miss", "forwarding disabled", "MTU", "TTL", "blackhole"} {
		t.Run(outcome, func(t *testing.T) {
			if err := b.UpdateFar(1, FarInfo{Action: 2}); err != nil {
				t.Fatal(err)
			}
			if err := b.PutPdrUplink(10, PdrInfo{SessionID: 42, PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true}); err != nil {
				t.Fatal(err)
			}
			command := func(args ...string) {
				t.Helper()
				if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
					t.Fatalf("ip %v: %v %s", args, err, out)
				}
			}
			command("route", "add", "203.0.113.0/24", "dev", "test-egress")
			t.Cleanup(func() {
				if out, err := exec.Command("ip", "route", "del", "203.0.113.0/24").CombinedOutput(); err != nil {
					t.Errorf("remove route: %v %s", err, out)
				}
			})
			command("neigh", "add", "203.0.113.2", "lladdr", "02:00:00:00:00:02", "nud", "permanent", "dev", "test-egress")
			t.Cleanup(func() { _ = exec.Command("ip", "neigh", "del", "203.0.113.2", "dev", "test-egress").Run() })
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{203, 0, 113, 1}, DstIP: net.IP{203, 0, 113, 2}}
			udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			switch outcome {
			case "unresolved neighbour":
				command("neigh", "del", "203.0.113.2", "dev", "test-egress")
			case "FIB miss":
				ip.DstIP = net.IP{203, 0, 114, 2}
			case "forwarding disabled":
				path := "/proc/sys/net/ipv4/conf/test-egress/forwarding"
				old, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("0\n"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(path, old, 0600); err != nil {
						t.Error(err)
					}
				})
			case "MTU":
				command("link", "set", "test-egress", "mtu", "68")
				t.Cleanup(func() {
					if out, err := exec.Command("ip", "link", "set", "test-egress", "mtu", "1500").CombinedOutput(); err != nil {
						t.Errorf("restore MTU: %v %s", err, out)
					}
				})
			case "TTL":
				ip.TTL = 1
			case "blackhole":
				command("route", "add", "blackhole", "203.0.113.2/32")
				t.Cleanup(func() {
					if out, err := exec.Command("ip", "route", "del", "blackhole", "203.0.113.2/32").CombinedOutput(); err != nil {
						t.Errorf("remove blackhole: %v %s", err, out)
					}
				})
			}
			iface, err := net.InterfaceByName("test-egress")
			if err != nil {
				t.Fatal(err)
			}
			context := &datapathContext{IngressIfindex: uint32(iface.Index)}
			packet := gtpDatapath(t, serializeDatapath(t, ip, udp, gopacket.Payload(make([]byte, 80))), nil, 0x30, false)
			action, want := runDatapath(t, b, packet, context)
			expected := uint32(2)
			if outcome == "blackhole" {
				expected = 1
			}
			if action != expected {
				t.Fatalf("ordinary action=%d want=%d", action, expected)
			}
			if err := b.UpdateFar(4, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7}); err != nil {
				t.Fatal(err)
			}
			if err := b.PutPdrUplink(10, PdrInfo{SessionID: 42, PdrID: 1, FarId: 4, OuterHeaderRemovalPresent: true}); err != nil {
				t.Fatal(err)
			}
			if got, _ := runDatapath(t, b, packet, context); got != 1 {
				t.Fatalf("admission action=%d", got)
			}
			reader.SetDeadline(time.Now().Add(time.Second))
			record, err := reader.Read()
			if err != nil {
				t.Fatal(err)
			}
			if err := b.UpdateFar(1, FarInfo{Action: 2, BufferSessionID: 42, BufferCookie: 7}); err != nil {
				t.Fatal(err)
			}
			result, err := b.RenderBufferedPacket(record, 1)
			if err != nil {
				t.Fatal(err)
			}
			if result.Action != action || action == 2 && !bytes.Equal(result.Frame, want) {
				t.Fatalf("fallback changed: action=%d expected=%d bytes_equal=%t", result.Action, action, bytes.Equal(result.Frame, want))
			}
			if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Sequence: record.Sequence, Downlink: record.Downlink}); err != nil {
				t.Fatal(err)
			}

		})
	}
}
