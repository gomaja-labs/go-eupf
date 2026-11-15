//go:build linux

package ebpf

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TS 29.244 V20.1.0 clause 5.2.3.1: NOCP observes receipt, including
// packets which cannot be retained. A different QoS flow remains eligible.
func TestBufferNoticeSurvivesEveryStorageBound(t *testing.T) {
	for _, bound := range []string{"session", "bar", "pool", "ring"} {
		t.Run(bound, func(t *testing.T) {
			b := loadDatapath(t)
			limit := uint32(1)
			if bound == "ring" {
				limit = 4096
			}
			if err := b.CreateBufferAnchor(42, limit, []BufferLane{{Cookie: 7, Mode: BufferHold, UsesBAR: bound == "bar"}}); err != nil {
				t.Fatal(err)
			}
			if bound == "bar" {
				if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 2, Limit: 4, BARLimit: 1, BARDLLimit: 1}); err != nil {
					t.Fatal(err)
				}
			}
			if bound == "pool" {
				if err := b.ConfigureBufferPool(1); err != nil {
					t.Fatal(err)
				}
				if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 2, Limit: 4, BARLimit: 4, BARDLLimit: 4}); err != nil {
					t.Fatal(err)
				}
			}
			if err := b.UpdateFar(3, FarInfo{Action: 12, BufferSessionID: 42, BufferCookie: 7}); err != nil {
				t.Fatal(err)
			}
			if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3, QerIDs: []uint32{1}, NRFlag: true}); err != nil {
				t.Fatal(err)
			}
			putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 1, QfiPresent: 1})
			n := 1
			if bound == "ring" {
				n = 2300
			}
			for range n {
				if action, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 2, 100)); err != nil || action != 1 {
					t.Fatalf("first input: %d %v", action, err)
				}
			}
			before, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
			if err != nil || before.Produced == 0 {
				t.Fatalf("storage did not fill: %+v %v", before, err)
			}
			putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 9, QfiPresent: 1})
			if action, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 2, 101, 63)); err != nil || action != 1 {
				t.Fatalf("overflow: %d %v", action, err)
			}
			after, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
			if err != nil || after.Produced != before.Produced {
				t.Fatalf("overflow acquired storage: %+v %v", after, err)
			}
			for _, qfi := range []uint8{1, 9} {
				notice, present, err := b.ReadBufferNotice(42, 7, 0)
				dscp := uint8(0)
				if qfi == 9 {
					dscp = 63
				}
				if err != nil || !present || !notice.QFIPresent || notice.QFI != qfi || notice.PDRID != 9 || notice.PPI != dscp {
					t.Fatalf("missing first-flow notice QFI=%d: %+v %t %v", qfi, notice, present, err)
				}
			}
			if _, present, err := b.ReadBufferNotice(42, 7, 0); err != nil || present {
				t.Fatalf("duplicate notice: %t %v", present, err)
			}
			if _, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 2, 102)); err != nil {
				t.Fatal(err)
			}
			if _, present, err := b.ReadBufferNotice(42, 7, 0); err != nil || present {
				t.Fatalf("same flow was not coalesced: %t %v", present, err)
			}
			outstanding, dropped, err := b.BufferPoolUsage()
			if err != nil || outstanding != uint32(after.Produced) || dropped == 0 {
				t.Fatalf("uncounted overflow: outstanding=%d dropped=%d error=%v", outstanding, dropped, err)
			}
		})
	}
}

func TestBufferOversizeDropStillNotifies(t *testing.T) {
	b := loadDatapath(t)
	if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateFar(3, FarInfo{Action: 12, BufferSessionID: 42, BufferCookie: 7}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}); err != nil {
		t.Fatal(err)
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 2}}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	packet := ethernetDatapath(t, layers.EthernetTypeIPv4, serializeDatapath(t, ip, udp, gopacket.Payload(make([]byte, 2100))))
	if action, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil || action != 1 {
		t.Fatalf("oversize input: %d %v", action, err)
	}
	if notice, present, err := b.ReadBufferNotice(42, 7, 0); err != nil || !present || notice.PDRID != 9 {
		t.Fatalf("oversize packet did not notify: %+v %t %v", notice, present, err)
	}
	if outstanding, dropped, err := b.BufferPoolUsage(); err != nil || outstanding != 0 || dropped != 1 {
		t.Fatalf("oversize drop not counted: outstanding=%d dropped=%d error=%v", outstanding, dropped, err)
	}
}

// TS 29.244 V20.1.0 clauses 8.2.30 and 8.2.100: lowering a suggested
// count constrains later admissions; already retained packets stay intact.
func TestBufferLowerBARCountPreservesRetainedPackets(t *testing.T) {
	b := loadDatapath(t)
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Cookie: 7, Mode: BufferHold, UsesBAR: true}}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateFar(3, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}); err != nil {
		t.Fatal(err)
	}
	for i := uint16(1); i <= 3; i++ {
		if _, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 2, i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 2, Limit: 4, BARLimit: 1, BARDLLimit: 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 2, 4)); err != nil {
		t.Fatal(err)
	}
	state, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
	if err != nil || state.Produced != 3 || state.Completed != 0 || state.Outstanding != 3 || state.BAROutstanding != 3 {
		t.Fatalf("lower count trimmed existing packets or admitted a later one: %+v %v", state, err)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		record, err := reader.Read()
		if err != nil || record.Sequence != seq {
			t.Fatalf("retained sequence %d: %+v %v", seq, record, err)
		}
		if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Sequence: seq, Downlink: true}); err != nil {
			t.Fatal(err)
		}
	}
	if outstanding, _, err := b.BufferPoolUsage(); err != nil || outstanding != 0 {
		t.Fatalf("pool did not reclaim packets: %d %v", outstanding, err)
	}
}
