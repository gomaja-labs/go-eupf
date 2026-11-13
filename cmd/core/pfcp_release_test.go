package core

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestOriginatedReleaseKeepsSessionsUntilCPRelease(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.91", 0)
	node := identityPeer(t, "127.0.0.91", 8805)
	identitySetup(t, conn, peer, "release.example")
	assoc := conn.associationByID("release.example")
	assoc.Sessions[11] = NewSession(11, 77, "", "", false)
	conn.requestTimeout = time.Second
	conn.requestRetries = 1
	conn.SendAssociationReleaseRequest()
	update := identityRead(t, node).(*message.AssociationUpdateRequest)
	period, err := update.GracefulReleasePeriod.GracefulReleasePeriod()
	if err != nil || period != 2*time.Second {
		t.Fatalf("release period %v: %v", period, err)
	}
	conn.serviceTransactions(time.Now().Add(time.Second))
	retry := identityRead(t, node)
	if retry.Sequence() != update.Sequence() {
		t.Fatal("release retry changed transaction")
	}
	conn.Handle(protocolWire(t, message.NewAssociationUpdateResponse(update.Sequence(), ie.NewNodeIDFQDN("release.example"), ie.NewCause(ie.CauseRequestAccepted))), node.LocalAddr().(*net.UDPAddr))
	if conn.GetAssiciationCount() != 1 || conn.GetSessionCount() != 1 {
		t.Fatal("Update acknowledgement released live sessions")
	}
	conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(3, ie.NewNodeIDFQDN("release.example"))), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.AssociationReleaseResponse)
	conn.serviceHeartbeats(time.Now())
	if cause, _ := response.Cause.Cause(); cause != ie.CauseRequestAccepted || conn.GetAssiciationCount() != 0 || conn.GetSessionCount() != 0 || len(conn.transport.pending) != 0 {
		t.Fatal("CP Release did not finish cleanup and retries")
	}
}

func TestOriginatedReleaseExpiresOnlyAfterGracefulPeriod(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.91", 0)
	node := identityPeer(t, "127.0.0.91", 8805)
	identitySetup(t, conn, peer, "release.example")
	conn.requestTimeout = time.Second
	conn.requestRetries = 1
	conn.SendAssociationReleaseRequest()
	_ = identityRead(t, node)
	conn.serviceHeartbeats(time.Now().Add(time.Second))
	if conn.GetAssiciationCount() != 1 {
		t.Fatal("release completed before grace period")
	}
	conn.serviceHeartbeats(time.Now().Add(conn.AssociationReleaseWaitTimeout() + time.Second))
	if conn.GetAssiciationCount() != 0 {
		t.Fatal("unanswered release exceeded configured local grace period")
	}
}

type releaseCleanupMaps struct {
	MapOperationsMock
	failures int
	attempts []time.Time
	delay    time.Duration
	finished []time.Time
}

func (m *releaseCleanupMaps) DeleteFar(uint32) error {
	m.attempts = append(m.attempts, time.Now())
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.finished = append(m.finished, time.Now())
	if len(m.attempts) <= m.failures {
		return errors.New("injected rule cleanup failure")
	}
	return nil
}
func (m *releaseCleanupMaps) BeginRuleTransaction(uint64) (ebpf.RuleTransaction, error) {
	return &mapTransactionMock{ForwardingPlaneController: m}, nil
}

func TestReleaseCleanupRetriesWithBackoffAndKeepsOwnership(t *testing.T) {
	conn := newProtocolConnection(t)
	maps := &releaseCleanupMaps{failures: 2}
	conn.mapOperations = maps
	peer := identityPeer(t, "127.0.0.92", 0)
	identitySetup(t, conn, peer, "cleanup.example")
	session := NewSession(11, 77, "", "", false)
	session.NewFar(1, 1, ebpf.FarInfo{Action: 1})
	conn.associationByID("cleanup.example").Sessions[11] = session
	conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(2, ie.NewNodeIDFQDN("cleanup.example"))), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.AssociationReleaseResponse)
	if cause, _ := response.Cause.Cause(); cause != ie.CauseRequestAccepted || conn.GetSessionCount() != 1 {
		t.Fatal("cleanup failure lost acceptance or ownership")
	}
	done := make(chan struct{})
	go func() { conn.Run(); close(done) }()
	defer func() { conn.Close(); <-done }()
	deadline := time.Now().Add(time.Second)
	for conn.GetAssiciationCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	conn.stateMu.RLock()
	attempts := append([]time.Time(nil), maps.attempts...)
	conn.stateMu.RUnlock()
	if conn.GetAssiciationCount() != 0 || len(attempts) != 3 {
		t.Fatalf("cleanup attempts %d, associations %d", len(attempts), conn.GetAssiciationCount())
	}
	if attempts[1].Sub(attempts[0]) < 90*time.Millisecond || attempts[2].Sub(attempts[1]) < 190*time.Millisecond {
		t.Fatal("cleanup retried without exponential backoff")
	}
}

func TestReleaseCleanupDeadlineNotifiesSupervisorAndRetainsResources(t *testing.T) {
	conn := newProtocolConnection(t)
	maps := &releaseCleanupMaps{failures: 1000}
	conn.mapOperations = maps
	resources, err := service.NewResourceManager("192.0.2.0/30", 1)
	if err != nil {
		t.Fatal(err)
	}
	conn.ResourceManager = resources
	if err := resources.FTEIDM.ReserveTEID(11, 1, 1); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("192.0.2.1")
	if err := resources.IPAM.ReserveIP(11, ip); err != nil {
		t.Fatal(err)
	}
	peer := identityPeer(t, "127.0.0.92", 0)
	identitySetup(t, conn, peer, "cleanup.example")
	session := NewSession(11, 77, "", "", false)
	session.NewFar(1, 1, ebpf.FarInfo{Action: 1})
	conn.associationByID("cleanup.example").Sessions[11] = session
	conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(2, ie.NewNodeIDFQDN("cleanup.example"))), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.AssociationReleaseResponse)
	if cause, _ := response.Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatal("cleanup failure changed unconditional Release acceptance")
	}
	conn.serviceHeartbeats(time.Now())
	conn.serviceHeartbeats(time.Now().Add(AssociationCleanupTimeout + time.Second))
	if conn.FatalError() == nil || conn.GetSessionCount() != 1 {
		t.Fatal("failed cleanup reported completion instead of terminal failure")
	}
	select {
	case err := <-conn.Failures():
		if err == nil {
			t.Fatal("nil fatal notification")
		}
	default:
		t.Fatal("supervisor was not notified")
	}
	if !errors.Is(resources.FTEIDM.ReserveTEID(99, 1, 1), service.ErrResourceCollision) || !errors.Is(resources.IPAM.ReserveIP(99, ip), service.ErrResourceCollision) {
		t.Fatal("installed session identifiers were freed after failed cleanup")
	}
	conn.Close()
	if conn.GetSessionCount() != 1 {
		t.Fatal("Close forgot ownership of unremoved rules")
	}
}

func TestHeartbeatFailureCannotShortenInitiatedReleasePeriod(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.91", 0)
	node := identityPeer(t, "127.0.0.91", 8805)
	identitySetup(t, conn, peer, "release.example")
	conn.SendAssociationReleaseRequest()
	_ = identityRead(t, node)
	conn.heartbeatFailed("release.example")
	if conn.GetAssiciationCount() != 1 {
		t.Fatal("heartbeat failure shortened graceful release")
	}
}

func TestHeartbeatCompletionKeepsSharedAddressNodeContextsSeparate(t *testing.T) {
	conn := newProtocolConnection(t)
	node := identityPeer(t, "127.0.0.93", 8805)
	for _, id := range []string{"first.example", "second.example"} {
		assoc := NewNodeAssociation(id, "127.0.0.93")
		assoc.endpoint = node.LocalAddr().String()
		conn.NodeAssociations[id] = assoc
	}
	conn.heartbeatTimeout = time.Second
	conn.serviceHeartbeats(time.Now())
	for range 2 {
		request := identityRead(t, node)
		response := message.NewHeartbeatResponse(request.Sequence(), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))
		conn.Handle(protocolWire(t, response), node.LocalAddr().(*net.UDPAddr))
	}
	for _, assoc := range conn.NodeAssociations {
		if assoc.heartbeatInFlight || assoc.RecoveryTimestamp.IsZero() {
			t.Fatal("matched heartbeat lost its Node ID context at a shared address")
		}
	}
}

func TestCleanupBackoffStartsAfterFailedAttemptCompletes(t *testing.T) {
	conn := newProtocolConnection(t)
	maps := &releaseCleanupMaps{failures: 1, delay: 30 * time.Millisecond}
	conn.mapOperations = maps
	assoc := NewNodeAssociation("cleanup.example", "127.0.0.92")
	session := NewSession(11, 77, "", "", false)
	session.NewFar(1, 1, ebpf.FarInfo{Action: 1})
	assoc.Sessions[11] = session
	conn.NodeAssociations[assoc.ID] = assoc
	conn.DeleteAssociation(assoc.ID)
	conn.serviceHeartbeats(time.Now())
	if len(maps.finished) != 1 {
		t.Fatal("cleanup attempt did not finish")
	}
	if assoc.cleanupNext.Sub(maps.finished[0]) < 100*time.Millisecond {
		t.Fatal("cleanup backoff elapsed during the failing map operation")
	}
}

func TestAssociationReleasePeriodUsesBoundedTwoSecondUnits(t *testing.T) {
	for _, tc := range []struct {
		interval time.Duration
		retries  uint32
		want     time.Duration
	}{
		{0, 0, 6 * time.Second}, {-time.Second, 0, 6 * time.Second}, {time.Second, 0, 2 * time.Second},
		{time.Second, 1, 2 * time.Second}, {time.Second, 2, 4 * time.Second}, {2 * time.Second, 3, 8 * time.Second},
		{2 * time.Second, 4, 8 * time.Second}, {3600 * time.Second, 100, 8 * time.Second}, {5 * time.Second, 0, 6 * time.Second},
	} {
		conn := newProtocolConnection(t)
		conn.requestTimeout, conn.requestRetries = tc.interval, tc.retries
		if got := conn.AssociationReleaseTimeout(); got != tc.want {
			t.Fatalf("T1 %v N1 %d: period %v want %v", tc.interval, tc.retries, got, tc.want)
		}
	}
	var disabled *PfcpConnection
	if disabled.AssociationReleaseTimeout() != 0 {
		t.Fatal("disabled optional connection changed shutdown bound")
	}
}

func TestCloseUsesNodeIdentityAtSharedAddresses(t *testing.T) {
	conn := newProtocolConnection(t)
	first := NewNodeAssociation("first.example", "127.0.0.1")
	second := NewNodeAssociation("second.example", "127.0.0.1")
	// Exercise the source-indexed registry used by older in-process fixtures.
	conn.NodeAssociations["127.0.0.1"] = first
	conn.NodeAssociations["127.0.0.2"] = second
	done := make(chan struct{})
	go func() { conn.Close(); close(done) }()
	select {
	case <-done:
		if conn.GetAssiciationCount() != 0 {
			t.Fatal("Close retained an association")
		}
	case <-time.After(100 * time.Millisecond):
		// Let the broken implementation terminate, so a failing regression leaves
		// neither a blocked cleanup nor a goroutine behind.
		conn.stateMu.Lock()
		conn.NodeAssociations = map[string]*NodeAssociation{first.ID: first, second.ID: second}
		conn.stateMu.Unlock()
		conn.DeleteAllAssociations()
		<-done
		t.Fatal("Close stalled on source-address keys shared by different Node IDs")
	}
}

func TestSuccessfulCleanupProgressHasNoFailureDeadline(t *testing.T) {
	conn := newProtocolConnection(t)
	assoc := NewNodeAssociation("cleanup.example", "127.0.0.92")
	for id := uint64(10); id < 80; id++ {
		assoc.Sessions[id] = NewSession(id, id, "", "", false)
	}
	conn.NodeAssociations[assoc.ID] = assoc
	conn.DeleteAssociation(assoc.ID)
	conn.serviceHeartbeats(time.Now().Add(10 * time.Second))
	if conn.FatalError() != nil {
		t.Fatal("successful cleanup was treated as a timed failure")
	}
	conn.serviceHeartbeats(time.Now().Add(20 * time.Second))
	if conn.GetSessionCount() != 0 || conn.GetAssiciationCount() != 0 {
		t.Fatal("cleanup did not finish")
	}
}

func TestReleasePeriodStartsAtAcceptedResponse(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.35", 0)
	node := identityPeer(t, "127.0.0.35", 8805)
	identitySetup(t, conn, peer, "release.example")
	conn.requestTimeout = time.Second
	conn.requestRetries = 2
	conn.SendAssociationReleaseRequest()
	request := identityRead(t, node)
	pending := conn.transport.pending[request.Sequence()]
	pending.lastSent = time.Now().Add(-time.Second)
	accepted := time.Now()
	conn.Handle(protocolWire(t, message.NewAssociationUpdateResponse(request.Sequence(), ie.NewNodeIDFQDN("release.example"), ie.NewCause(1))), node.LocalAddr().(*net.UDPAddr))
	assoc := conn.associationByID("release.example")
	if assoc.releaseDeadline.Before(accepted.Add(conn.AssociationReleaseTimeout())) {
		t.Fatal("accepted retransmission shortened the CP's full graceful period")
	}
}

func TestShutdownRefusesSetupEvenOnAnIdleConnection(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.BeginShutdown()
	conn.SendAssociationReleaseRequest()
	peer := identityPeer(t, "127.0.0.36", 0)
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("new.example"), ie.NewRecoveryTimeStamp(time.Now()))), peer.LocalAddr().(*net.UDPAddr))
	reply := identityRead(t, peer).(*message.AssociationSetupResponse)
	if cause, _ := reply.Cause.Cause(); cause != ie.CauseNoResourcesAvailable || conn.GetAssiciationCount() != 0 {
		t.Fatal("idle connection reopened Setup during process shutdown")
	}
}

func TestShutdownCancelsPendingAndRefusesRacingOriginatedSetup(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.40", 0)
	first := message.NewAssociationSetupRequest(0, ie.NewNodeIDFQDN("up.example"), ie.NewRecoveryTimeStamp(time.Now()))
	if err := conn.SendMessage(first, peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = identityRead(t, peer)
	request := conn.transport.pending[first.Sequence()]
	conn.BeginShutdown()
	if !request.completed || len(conn.transport.pending) != 0 {
		t.Fatal("shutdown left an originated Setup pending")
	}
	next := message.NewAssociationSetupRequest(0, ie.NewNodeIDFQDN("up.example"), ie.NewRecoveryTimeStamp(time.Now()))
	if err := conn.SendMessage(next, peer.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("Setup raced past the shutdown latch")
	}
	if unexpected := pipelineRead(t, peer, 10*time.Millisecond); unexpected != nil {
		t.Fatal("originated Setup sent during shutdown")
	}
}

func TestTransientCleanupFailureDoesNotLimitHealthyProgress(t *testing.T) {
	conn := newProtocolConnection(t)
	maps := &releaseCleanupMaps{failures: 1}
	conn.mapOperations = maps
	peer := identityPeer(t, "127.0.0.93", 0)
	identitySetup(t, conn, peer, "slow.example")
	assoc := conn.associationByID("slow.example")
	const sessions = 64*4 + 1
	for id := uint64(1); id <= sessions; id++ {
		s := NewSession(id, 1000+id, "", "", false)
		s.NewFar(1, uint32(id), ebpf.FarInfo{Action: 1})
		assoc.Sessions[id] = s
	}
	conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(2, ie.NewNodeIDFQDN("slow.example"))), peer.LocalAddr().(*net.UDPAddr))
	if response := identityRead(t, peer).(*message.AssociationReleaseResponse); pipelineCause(t, response) != ie.CauseRequestAccepted {
		t.Fatal("release not accepted")
	}
	step := func(at time.Time) (int, error) {
		conn.stateMu.Lock()
		conn.serviceReleasesLocked(at)
		remaining := len(assoc.Sessions)
		err := conn.terminalError
		conn.stateMu.Unlock()
		return remaining, err
	}
	start := time.Now()
	// Batch 1: the first deletion fails once (transient), 63 succeed.
	remaining, err := step(start)
	t.Logf("after batch 1: remaining=%d deletions=%d err=%v", remaining, len(maps.attempts), err)
	// Batches 2 and 3 succeed completely (pacing as on the real data plane).
	for i, at := range []time.Duration{200 * time.Millisecond, 400 * time.Millisecond} {
		remaining, err = step(start.Add(at))
		t.Logf("after batch %d at +%s: remaining=%d deletions=%d err=%v", i+2, at, remaining, len(maps.attempts), err)
		if err != nil {
			t.Fatalf("early fatal: %v", err)
		}
	}
	// A later healthy batch, 3.5 s after the single failure: progress continues.
	remaining, err = step(start.Add(3500 * time.Millisecond))
	t.Logf("after batch at +3.5s: remaining=%d deletions=%d failures_injected=%d err=%v", remaining, len(maps.attempts), maps.failures, err)
	if err != nil {
		t.Fatalf("slow but successful cleanup declared terminal after one transient failure: %v", err)
	}
}
