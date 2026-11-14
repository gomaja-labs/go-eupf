//go:build linux

package core

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// Packet storage cannot limit metadata admission. The fixture uses real BPF
// maps but bypasses PFCP capability rejection while buffering is staged.
func TestPacketBufferAdmitsEveryConfiguredSession(t *testing.T) {
	pipelineQuiet(t)
	const count = 16384
	plane, buffering, conn, assoc, _, peer := packetBufferFixtureOptions(t, BufferingOptions{Packets: 4096, PerSession: 4, FrameBytes: 2048, Retention: time.Minute}, func(plane *ebpf.BpfObjects) {
		plane.SetBufferCapacity(count, 4096)
		plane.SetFarMapSize(2 * count)
		plane.SetPdrMapSize(2 * count)
	})
	t.Cleanup(func() { conn.stateMu.Lock(); defer conn.stateMu.Unlock(); clear(assoc.Sessions) })
	for id := uint64(1); id <= count; id++ {
		func() {
			conn.stateMu.Lock()
			defer conn.stateMu.Unlock()
			session := NewSession(id, id+100000, "", "", false)
			session.Is5G = true
			session.CPFSEIDIPv4 = net.ParseIP("127.0.0.92")
			session.FARs[1] = SFarInfo{FarInfo: ebpf.FarInfo{Action: 12}}
			owner, err := conn.reservePacketBuffers(assoc, session)
			if err != nil {
				t.Fatalf("BUFF session %d/%d rejected: %v", id, count, err)
			}
			assoc.Sessions[id] = session
			conn.activatePacketBuffers(owner)
			far := session.FARs[1]
			// One immutable slot is used only by this synthetic serial producer;
			// session admission and anchor identities are independent of that slot.
			if err := plane.UpdateFar(3, far.FarInfo); err != nil {
				t.Fatal(err)
			}
			destination := net.IP{198, 18, byte(id >> 8), byte(id)}
			if err := plane.PutPdrDownlink(destination, ebpf.PdrInfo{SessionID: id, PdrID: 9, FarId: 3}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacketFor(t, uint16(id), destination)); err != nil {
				t.Fatal(err)
			}
			notice, present, err := plane.ReadBufferNotice(id, far.FarInfo.BufferCookie, far.FarInfo.BufferLane)
			if err != nil || !present || notice.PDRID != 9 {
				t.Fatalf("first packet of session %d did not notify: present=%t error=%v", id, present, err)
			}
			conn.noteDownlinkPacketLocked(session, 1, notice, time.Now())
			if len(session.downlink.pending) != 1 {
				t.Fatalf("session %d has no eligible DLDR", id)
			}
		}()
		if id <= 4096 && id%32 == 0 {
			deadline := time.Now().Add(2 * time.Second)
			for {
				buffering.mu.Lock()
				free := len(buffering.free)
				buffering.mu.Unlock()
				if free == 4096-int(id) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("reader stalled at session %d: free=%d", id, free)
				}
				time.Sleep(time.Millisecond)
			}
		}
	}
	outstanding, dropped, err := plane.BufferPoolUsage()
	if err != nil || outstanding != 4096 || dropped != 12288 {
		t.Fatalf("pool bound/count: outstanding=%d dropped=%d error=%v", outstanding, dropped, err)
	}
	if len(buffering.owners) != count {
		t.Fatalf("accepted %d sessions, want %d", len(buffering.owners), count)
	}
	if err := peer.SetReadBuffer(4 << 20); err != nil {
		t.Fatal(err)
	}
	conn.requestTimeout, conn.requestRetries = time.Second, 10
	conn.maxOriginatedRequests = 128
	var capture *bufferPFCPCapture
	if os.Getenv("EUPF_BUFFER_CAPTURE_DIR") != "" {
		capture = startBufferPFCPCapture(t, 8<<20)
	}
	go conn.Run()
	seen := make(map[uint64]bool, count)
	for len(seen) < count {
		report := readBufferWireReport(t, peer)
		id := report.SEID() - 100000
		if id < 1 || id > count || report.DownlinkDataReport == nil {
			t.Fatalf("unexpected DLDR SEID=%d", report.SEID())
		}
		seen[id] = true
		response := message.NewSessionReportResponse(id, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))
		if _, err := peer.WriteToUDP(protocolWire(t, response), conn.socket().LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn.transport.mu.Lock()
		pending := len(conn.transport.pending)
		conn.transport.mu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile("/proc/net/snmp")
			t.Logf("UDP fixture counters: %s", raw)
			t.Fatalf("%d reports not completed", pending)
		}
		time.Sleep(time.Millisecond)
	}
	if capture != nil {
		capture.close()
		if capture.err != nil {
			t.Fatal(capture.err)
		}
		dir := os.Getenv("EUPF_BUFFER_CAPTURE_DIR")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "buffer-sessions-16384.pcap"), capture.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("accepted=%d notified=%d stored=%d overflow=%d", len(buffering.owners), len(seen), outstanding, dropped)

	select {
	case err := <-buffering.Failures():
		t.Fatal(err)
	default:
	}
}
