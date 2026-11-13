//go:build linux

package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func packetBufferFixture(t *testing.T) (*ebpf.BpfObjects, *PacketBuffering, *PfcpConnection, *NodeAssociation, *Session, *net.UDPConn) {
	t.Helper()
	if err := ebpf.IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	plane := ebpf.NewBpfObjects()
	if err := plane.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := plane.Close(); err != nil {
			t.Error(err)
		}
	})
	conn, assoc, session, peer := downlinkFixture(t, true)
	conn.mapOperations = plane
	buffering, err := NewPacketBuffering(plane, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: 2048, Retention: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := buffering.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := conn.SetPacketBuffering(buffering); err != nil {
		t.Fatal(err)
	}
	session.FARs = map[uint32]SFarInfo{1: {FarInfo: ebpf.FarInfo{Action: 12}}}
	session.downlink = nil
	t.Cleanup(func() {
		conn.stateMu.Lock()
		for id, far := range session.FARs {
			if far.GlobalId == 0 {
				delete(session.FARs, id)
			}
		}
		conn.stateMu.Unlock()
	})
	return plane, buffering, conn, assoc, session, peer
}
func bufferKernelPacket(t *testing.T, id uint16) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Id: id, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 2}}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload([]byte{1, 2, 3, 4})); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestApplicationBufferReaderPreservesPacketsAndWaitsForCommit(t *testing.T) {
	plane, buffering, conn, assoc, session, peer := packetBufferFixture(t)
	conn.stateMu.Lock()
	owner, err := conn.reservePacketBuffers(assoc, session)
	conn.stateMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := plane.BeginRuleTransaction(11)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	slot, err := tx.GetNextFAR()
	if err != nil {
		t.Fatal(err)
	}
	far := session.FARs[1]
	far.GlobalId = slot
	session.FARs[1] = far
	if err := tx.UpdateFar(slot, far.FarInfo); err != nil {
		t.Fatal(err)
	}
	if err := tx.PutPdrDownlink(net.IP{198, 51, 100, 2}, ebpf.PdrInfo{SessionID: 11, PdrID: 9, FarId: slot, NRFlag: true}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	go conn.Run()
	for _, id := range []uint16{100, 101} {
		action, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id))
		if err != nil || action != 1 {
			t.Fatalf("buffer input action=%d error=%v", action, err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		conn.stateMu.RLock()
		received := owner.cycles[0].received
		conn.stateMu.RUnlock()
		if received == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("application reader did not consume admitted packets")
		}
		time.Sleep(time.Millisecond)
	}
	conn.transport.mu.Lock()
	pending := len(conn.transport.pending)
	conn.transport.mu.Unlock()
	if pending != 0 {
		t.Fatal("uncommitted buffering generated a report")
	}
	conn.stateMu.Lock()
	conn.activatePacketBuffers(owner)
	conn.stateMu.Unlock()
	report, ok := identityRead(t, peer).(*message.SessionReportRequest)
	if !ok || report.DownlinkDataReport == nil {
		t.Fatal("application reader did not deliver DLDR")
	}
	conn.stateMu.RLock()
	cycle := owner.cycles[0]
	first := buffering.entries[cycle.head]
	second := buffering.entries[first.next]
	if first.record.Sequence != 1 || second.record.Sequence != 2 || binary.BigEndian.Uint16(first.record.Packet[18:20]) != 100 || binary.BigEndian.Uint16(second.record.Packet[18:20]) != 101 {
		conn.stateMu.RUnlock()
		t.Fatal("ring reuse changed buffered bytes or their order")
	}
	conn.stateMu.RUnlock()
	if err := buffering.Close(); err != nil {
		t.Fatal(err)
	}
	buffering.mu.Lock()
	reserved, available := buffering.reserved, len(buffering.free)
	buffering.mu.Unlock()
	if reserved != 0 || available != 8 {
		t.Fatalf("canceled pool reserve=%d free=%d", reserved, available)
	}
}

func TestPacketBufferReservationIsGlobalAndPrecedesPublication(t *testing.T) {
	_, buffering, conn, assoc, first, _ := packetBufferFixture(t)
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if _, err := conn.reservePacketBuffers(assoc, first); err != nil {
		t.Fatal(err)
	}
	second := NewSession(12, 78, "", "", false)
	if _, err := conn.reservePacketBuffers(assoc, second); err != nil {
		t.Fatal(err)
	}
	third := NewSession(13, 79, "", "", false)
	if _, err := conn.reservePacketBuffers(assoc, third); err == nil {
		t.Fatal("third reservation exceeded the shared packet budget")
	}
	if raw, err := buffering.plane.BufferAnchors.LookupBytes(uint64(13)); err != nil || raw != nil {
		t.Fatalf("unreserved anchor lookup length=%d error=%v", len(raw), err)
	}
}

func TestSessionJournalReservesAndRollsBackPacketBuffers(t *testing.T) {
	_, buffering, conn, assoc, session, _ := packetBufferFixture(t)
	conn.stateMu.Lock()
	if err := conn.ResourceManager.AdmitSession(session.LocalSEID); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	start, finish := conn.prepareSessionMutation(session, createSessionMutation)
	defer func() {
		conn.stateMu.Lock()
		err := finish(false)
		conn.stateMu.Unlock()
		if err != nil {
			t.Error(err)
		}
	}()
	conn.stagePacketBuffering(assoc, nil, session, createSessionMutation, false)
	if err := start(); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	if session.buffers == nil {
		conn.stateMu.Unlock()
		t.Fatal("session journal published without reserving packet buffers")
	}
	owner := session.buffers.owner
	if err := finish(false); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	conn.stateMu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn.stateMu.RLock()
		released := owner.released
		conn.stateMu.RUnlock()
		if released {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rollback did not return its packet reservation")
		}
		time.Sleep(time.Millisecond)
	}
	buffering.mu.Lock()
	reserved := buffering.reserved
	buffering.mu.Unlock()
	if reserved != 0 {
		t.Fatalf("rollback retained %d packet credits", reserved)
	}
}

func publishPacketBufferFixture(t *testing.T) (*ebpf.BpfObjects, *PacketBuffering, *PfcpConnection, *NodeAssociation, *Session, *net.UDPConn) {
	t.Helper()
	plane, buffering, conn, assoc, session, peer := packetBufferFixture(t)
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if err := conn.ResourceManager.AdmitSession(session.LocalSEID); err != nil {
		t.Fatal(err)
	}
	start, finish := conn.prepareSessionMutation(session, createSessionMutation)
	defer func() {
		if err := finish(false); err != nil {
			t.Error(err)
		}
	}()
	conn.stagePacketBuffering(assoc, nil, session, createSessionMutation, false)
	if err := start(); err != nil {
		t.Fatal(err)
	}
	slot, err := conn.mapOperations.GetNextFAR()
	if err != nil {
		t.Fatal(err)
	}
	far := session.FARs[1]
	far.GlobalId = slot
	session.FARs[1] = far
	if err := conn.mapOperations.UpdateFar(slot, far.FarInfo); err != nil {
		t.Fatal(err)
	}
	farID := uint32(1)
	session.PDRs[9] = SPDRInfo{FARID: &farID, PdrID: 9, Ipv4: net.IP{198, 51, 100, 2}, SourceInterface: 1, PdrInfo: ebpf.PdrInfo{SessionID: 11, PdrID: 9, NRFlag: true}}
	if err := conn.rebindSessionRules(session); err != nil {
		t.Fatal(err)
	}
	if err := finish(true); err != nil {
		t.Fatal(err)
	}
	return plane, buffering, conn, assoc, session, peer
}

func TestDownlinkDropResponseCancelsActualAdmittedPackets(t *testing.T) {
	plane, buffering, conn, assoc, session, peer := publishPacketBufferFixture(t)
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		conn.stateMu.RLock()
		notices := len(session.downlink.pending)
		conn.stateMu.RUnlock()
		if notices != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual admitted packet did not queue DLDR")
		}
		time.Sleep(time.Millisecond)
	}
	conn.serviceDownlinkNotifications(time.Now())
	first := identityRead(t, peer).(*message.SessionReportRequest)
	oldFar := session.FARs[1]
	response := message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseRequestAccepted), ie.NewPFCPSRRspFlags(1))
	conn.Handle(protocolWire(t, response), peer.LocalAddr().(*net.UDPAddr))
	conn.stateMu.RLock()
	replacement := assoc.Sessions[11]
	newFar := replacement.FARs[1]
	conn.stateMu.RUnlock()
	if oldFar.GlobalId == newFar.GlobalId || oldFar.FarInfo.BufferCookie == newFar.FarInfo.BufferCookie {
		t.Fatal("DROBU did not publish a new buffering lifetime through a fresh FAR")
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		buffering.mu.Lock()
		held := len(buffering.entries) - len(buffering.free)
		buffering.mu.Unlock()
		if held == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DROBU retained its canceled payload")
		}
		time.Sleep(time.Millisecond)
	}
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 101)); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for {
		conn.serviceDownlinkNotifications(time.Now())
		conn.transport.mu.Lock()
		pending := len(conn.transport.pending)
		conn.transport.mu.Unlock()
		if pending != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DROBU did not rearm actual packet admission")
		}
		time.Sleep(time.Millisecond)
	}
	_ = identityRead(t, peer)
}
