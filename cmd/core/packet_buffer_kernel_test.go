//go:build linux

package core

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func packetBufferFixture(t *testing.T) (*ebpf.BpfObjects, *PacketBuffering, *PfcpConnection, *NodeAssociation, *Session, *net.UDPConn) {
	return packetBufferFixtureOptions(t, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
}
func packetBufferFixtureOptions(t *testing.T, options BufferingOptions, configure ...func(*ebpf.BpfObjects)) (*ebpf.BpfObjects, *PacketBuffering, *PfcpConnection, *NodeAssociation, *Session, *net.UDPConn) {
	t.Helper()
	return packetBufferFixtureStartOptions(t, true, options, configure...)
}
func packetBufferFixtureStartOptions(t *testing.T, start bool, options BufferingOptions, configure ...func(*ebpf.BpfObjects)) (*ebpf.BpfObjects, *PacketBuffering, *PfcpConnection, *NodeAssociation, *Session, *net.UDPConn) {
	t.Helper()
	if err := ebpf.IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	plane := ebpf.NewBpfObjects()
	for _, apply := range configure {
		apply(plane)
	}
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
	buffering, err := NewPacketBuffering(plane, options)
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
	if start {
		<-buffering.Start(context.Background())
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
	return bufferKernelPacketFor(t, id, net.IP{198, 51, 100, 2})
}
func bufferKernelPacketFor(t *testing.T, id uint16, destination net.IP, content ...[]byte) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Id: id, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 51, 100, 1}, DstIP: destination}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	payload := []byte{1, 2, 3, 4}
	if len(content) != 0 {
		payload = content[0]
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload(payload)); err != nil {
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

// TS 29.244 V20.1.0 clause 5.2.3.1: accepting BUFF does not reserve packets.
func TestPacketBufferSessionsDoNotReserveStorage(t *testing.T) {
	_, buffering, conn, assoc, _, _ := packetBufferFixture(t)
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	for id := uint64(11); id < 27; id++ {
		session := NewSession(id, id+100, "", "", false)
		session.FARs[1] = SFarInfo{FarInfo: ebpf.FarInfo{Action: 12}}
		if _, err := conn.reservePacketBuffers(assoc, session); err != nil {
			t.Fatalf("BUFF session %d rejected with an empty pool: %v", id, err)
		}
	}
	buffering.mu.Lock()
	free := len(buffering.free)
	buffering.mu.Unlock()
	if free != 8 {
		t.Fatalf("accepting sessions consumed packet storage: free=%d", free)
	}
}

func TestSessionJournalReservesAndRollsBackPacketBuffers(t *testing.T) {
	_, buffering, conn, assoc, session, _ := packetBufferFixture(t)
	conn.stateMu.Lock()
	if err := conn.ResourceManager.AdmitSession(session.LocalSEID); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	start, finish := conn.prepareSessionMutation(session, createSessionMutation, true)
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
	return publishPacketBufferFixtureOptions(t, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
}
func publishPacketBufferFixtureOptions(t *testing.T, options BufferingOptions) (*ebpf.BpfObjects, *PacketBuffering, *PfcpConnection, *NodeAssociation, *Session, *net.UDPConn) {
	t.Helper()
	plane, buffering, conn, assoc, session, peer := packetBufferFixtureOptions(t, options)
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if err := conn.ResourceManager.AdmitSession(session.LocalSEID); err != nil {
		t.Fatal(err)
	}
	start, finish := conn.prepareSessionMutation(session, createSessionMutation, true)
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

type bufferSenderFunc func(ebpf.RenderedBuffer) error

func (send bufferSenderFunc) Prepare() error                        { return nil }
func (send bufferSenderFunc) Send(packet ebpf.RenderedBuffer) error { return send(packet) }
func (send bufferSenderFunc) Close() error                          { return nil }

func switchBufferedFARToForward(t *testing.T, conn *PfcpConnection, assoc *NodeAssociation, before *Session, extraGrace ...<-chan struct{}) *Session {
	t.Helper()
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	after := cloneSession(before)
	far := after.FARs[1]
	far.FarInfo.Action = 2
	far.FarInfo.OuterHeaderCreation = 1
	far.FarInfo.RemoteIP = binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2})
	far.FarInfo.Teid = 200
	after.FARs[1] = far
	start, finish := conn.prepareSessionMutation(after, updateSessionMutation, true)
	defer func() {
		if err := finish(false); err != nil {
			t.Error(err)
		}
	}()
	conn.stagePacketBuffering(assoc, before, after, updateSessionMutation, false)
	if err := start(); err != nil {
		t.Fatal(err)
	}
	if err := finish(true); err != nil {
		t.Fatal(err)
	}
	assoc.Sessions[after.LocalSEID] = after
	for _, additional := range extraGrace {
		cycle := after.buffers.cycles[1]
		original, joined := cycle.grace, make(chan struct{})
		cycle.grace = joined
		go func() {
			<-original
			<-additional
			close(joined)
		}()
	}
	return after
}

func TestApplicationBufferDrainTransmitsInOrder(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixture(t)
	packetBufferRoute(t, plane)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan uint16, 4)
	buffering.sender = bufferSenderFunc(func(packet ebpf.RenderedBuffer) error {
		if len(packet.Frame) < 56 {
			return errors.New("short rendered packet")
		}
		select {
		case delivered <- binary.BigEndian.Uint16(packet.Frame[54:56]):
		default:
			return errors.New("test receiver full")
		}
		return nil
	})
	for _, id := range []uint16{100, 101} {
		if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	_ = switchBufferedFARToForward(t, conn, assoc, session)
	for _, want := range []uint16{100, 101} {
		select {
		case got := <-delivered:
			if got != want {
				t.Fatalf("packet order=%d want=%d", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("application did not transmit the buffered packet")
		}
	}
	select {
	case <-delivered:
		t.Fatal("buffered packet was transmitted twice")
	case <-time.After(50 * time.Millisecond):
	}
}

func packetBufferRoute(t *testing.T, plane *ebpf.BpfObjects) {
	t.Helper()
	commands := [][]string{
		{"link", "add", "buffer-output", "type", "veth", "peer", "name", "buffer-input"},
		{"link", "set", "buffer-output", "up"}, {"link", "set", "buffer-input", "up"},
		{"addr", "add", "198.18.1.1/24", "dev", "buffer-output"},
		{"neigh", "add", "198.18.1.2", "lladdr", "02:00:00:00:00:02", "nud", "permanent", "dev", "buffer-output"},
	}
	for _, args := range commands {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, output)
		}
	}
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "link", "del", "buffer-output").CombinedOutput(); err != nil {
			t.Errorf("remove packet route: %v %s", err, out)
		}
	})
	path := "/proc/sys/net/ipv4/conf/all/forwarding"
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(path, before, 0600); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := ebpf.IpEntrypointDataplaneConfig{N3Ipv4Address: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 1}), N9Ipv4Address: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 2})}
	if err := plane.GlobalConfig.Set(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationBufferDrainRetriesOnlyAcknowledgement(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixture(t)
	packetBufferRoute(t, plane)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan uint16, 8)
	buffering.sender = bufferSenderFunc(func(packet ebpf.RenderedBuffer) error {
		select {
		case delivered <- binary.BigEndian.Uint16(packet.Frame[54:56]):
		default:
			return errors.New("test receiver full")
		}
		return nil
	})
	var attempts atomic.Int32
	buffering.complete = func(command ebpf.BufferCommand) (ebpf.BufferCommand, error) {
		if attempts.Add(1) == 1 {
			return ebpf.BufferCommand{}, errors.New("synthetic acknowledgement failure")
		}
		return plane.BufferControl(command)
	}
	for _, id := range []uint16{100, 101} {
		if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	_ = switchBufferedFARToForward(t, conn, assoc, session)
	for _, want := range []uint16{100, 101} {
		select {
		case got := <-delivered:
			if got != want {
				t.Fatalf("ACK retry transmitted %d want %d", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ACK failure stalled the ordered queue")
		}
	}
	deadline := time.Now().Add(time.Second)
	for attempts.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("kernel completion was not retried")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-delivered:
		t.Fatal("ACK retry repeated transmission")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case err := <-buffering.Failures():
		t.Fatalf("transient ACK became terminal: %v", err)
	default:
	}
}

func TestApplicationBufferDeletionWaitsForOutputAndCancelsRemainder(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixture(t)
	packetBufferRoute(t, plane)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var sends atomic.Int32
	buffering.sender = bufferSenderFunc(func(ebpf.RenderedBuffer) error {
		if sends.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	})
	for _, id := range []uint16{100, 101} {
		if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	session = switchBufferedFARToForward(t, conn, assoc, session)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("output worker did not start")
	}
	mutationStarted, deleted := make(chan struct{}), make(chan error, 1)
	go func() {
		conn.stateMu.Lock()
		defer conn.stateMu.Unlock()
		close(mutationStarted)
		err := conn.DeleteSession(session)
		if err == nil {
			conn.forgetSession(assoc, session.LocalSEID)
		}
		deleted <- err
	}()
	<-mutationStarted
	select {
	case err := <-deleted:
		t.Fatalf("deletion completed while output was still running: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	buffering.mu.Lock()
	reserved := buffering.reserved
	buffering.mu.Unlock()
	if reserved != 1 {
		t.Fatalf("in-flight output lost its reservation: %d", reserved)
	}
	unblock()
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deletion did not finish after output completion")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		buffering.mu.Lock()
		reserved = buffering.reserved
		buffering.mu.Unlock()
		if reserved == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("successful deletion did not reclaim the queue")
		}
		time.Sleep(time.Millisecond)
	}
	if sends.Load() != 1 {
		t.Fatalf("deletion transmitted %d packets", sends.Load())
	}
}

func TestApplicationBufferDrainReclaimsItsGuardAndReservation(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixture(t)
	packetBufferRoute(t, plane)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	var sends atomic.Int32
	buffering.sender = bufferSenderFunc(func(ebpf.RenderedBuffer) error { sends.Add(1); return nil })
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	_ = switchBufferedFARToForward(t, conn, assoc, session)
	deadline := time.Now().Add(2 * time.Second)
	for {
		buffering.mu.Lock()
		reserved := buffering.reserved
		buffering.mu.Unlock()
		if reserved == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completed drain retained its anchor reservation")
		}
		time.Sleep(time.Millisecond)
	}
	conn.stateMu.RLock()
	current := assoc.Sessions[11]
	far := current.FARs[1]
	conn.stateMu.RUnlock()
	if current.buffers != nil || far.FarInfo.BufferSessionID != 0 || far.FarInfo.BufferCookie != 0 || sends.Load() != 1 {
		t.Fatal("completed drain did not publish ordinary forwarding")
	}
	kernelFar, err := plane.GetFar(far.GlobalId)
	if err != nil || kernelFar.BufferSessionID != 0 || kernelFar.Action != 2 {
		t.Fatalf("kernel forwarding guard: %+v %v", kernelFar, err)
	}
}

func TestPacketBufferReclamationRequiresTerminalAndProducerGrace(t *testing.T) {
	plane, buffering, conn, _, session, _ := publishPacketBufferFixture(t)
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	owner := session.buffers.owner
	deadline := time.Now().Add(time.Second)
	for {
		conn.stateMu.RLock()
		received := owner.cycles[0].received
		conn.stateMu.RUnlock()
		if received == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reader did not consume the record")
		}
		time.Sleep(time.Millisecond)
	}
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	cycle := owner.cycles[0]
	if _, err := plane.BufferControl(ebpf.BufferCommand{SessionID: 11, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferDiscard}); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	close(closed)
	owner.canceled, owner.graced, owner.terminal, owner.grace = true, false, false, closed
	cycle.canceled, cycle.terminal, cycle.grace = true, false, closed
	buffering.serviceOwner(owner, time.Now())
	if cycle.head == noBufferedPacket || owner.released {
		t.Fatal("reclamation ran before a successful terminal result")
	}
	pending := make(chan struct{})
	owner.terminal, owner.grace = true, pending
	cycle.terminal, cycle.grace = true, pending
	buffering.serviceOwner(owner, time.Now())
	if cycle.head == noBufferedPacket || owner.released {
		t.Fatal("reclamation ran before producer grace")
	}
	if err := plane.SynchronizeRules(); err != nil {
		t.Fatal(err)
	}
	close(pending)
	buffering.serviceOwner(owner, time.Now())
	if !owner.released || cycle.head != noBufferedPacket {
		t.Fatal("all completed signals did not reclaim the reservation")
	}
}

func TestPacketBufferReclamationWaitsForUnreadRecords(t *testing.T) {
	plane, buffering, conn, _, session, _ := publishPacketBufferFixture(t)
	owner := session.buffers.owner
	conn.stateMu.Lock()
	cycle := owner.cycles[0]
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	if _, err := plane.BufferControl(ebpf.BufferCommand{SessionID: 11, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferDiscard}); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	if err := plane.SynchronizeRules(); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	closed := make(chan struct{})
	close(closed)
	owner.canceled, owner.terminal, owner.grace = true, true, closed
	cycle.canceled, cycle.terminal, cycle.grace = true, true, closed
	buffering.serviceOwner(owner, time.Now())
	if owner.released {
		conn.stateMu.Unlock()
		t.Fatal("producer grace released an unread admitted record")
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
			t.Fatal("consumed record did not finish cancellation")
		}
		time.Sleep(time.Millisecond)
	}
}
