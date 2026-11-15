package core

import (
	"errors"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestSessionInactivityTimerIsAcceptedAtSessionLevel(t *testing.T) {
	conn := sessionLimitConnection(t, 16, nil, nil)
	conn.mapOperations = &activityPlane{MapOperationsMock: &MapOperationsMock{}}
	peer := identityPeer(t, "127.0.0.25", 8805)
	identitySetup(t, conn, peer, "inactive.example")
	req := sessionLimitRequest("inactive.example", 2, 1)
	req.UserPlaneInactivityTimer = ie.NewUserPlaneInactivityTimer(2 * time.Second)
	conn.Handle(protocolWire(t, req), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.SessionEstablishmentResponse)
	if cause := pipelineCause(t, response); cause != ie.CauseRequestAccepted {
		t.Fatalf("session timer rejected with cause %d", cause)
	}
}

// The fixture serializes synthetic counter changes with PFCP calls, as stateMu
// serializes sampling. The real map is exercised separately by kernel tests.
type activityPlane struct {
	*MapOperationsMock
	count     uint64
	released  []uint32
	active    bool
	failRead  bool
	failBegin bool
}

func (p *activityPlane) BeginRuleTransaction(id uint64) (ebpf.RuleTransaction, error) {
	if p.failBegin {
		return nil, errors.New("synthetic transaction failure")
	}
	before := *p.MapOperationsMock
	return &mapTransactionMock{ForwardingPlaneController: p, rollback: func() { *p.MapOperationsMock = before }}, nil
}
func (p *activityPlane) NewSessionActivity() (uint32, uint64, error) {
	if p.active {
		return 0, 0, ebpf.ErrRuleCapacity
	}
	p.active = true
	return 1, p.count, nil
}
func (p *activityPlane) SessionActivityCount(uint32) (uint64, error) {
	if p.failRead {
		return 0, errors.New("synthetic counter failure")
	}
	return p.count, nil
}
func (p *activityPlane) ReleaseSessionActivity(slot uint32) {
	p.active = false
	p.released = append(p.released, slot)
}

func inactivityFixture(t *testing.T, timer time.Duration, local time.Duration) (*PfcpConnection, *NodeAssociation, *Session, *activityPlane, *net.UDPConn) {
	t.Helper()
	conn := sessionLimitConnection(t, 16, nil, nil)
	conn.inactivityReleaseTimeout = local
	plane := &activityPlane{MapOperationsMock: &MapOperationsMock{}}
	conn.mapOperations = plane
	peer := identityPeer(t, "127.0.0.25", 8805)
	identitySetup(t, conn, peer, "inactive.example")
	request := sessionLimitRequest("inactive.example", 2, 1)
	if timer > 0 {
		request.UserPlaneInactivityTimer = ie.NewUserPlaneInactivityTimer(timer)
	}
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.SessionEstablishmentResponse)
	if pipelineCause(t, response) != 1 {
		t.Fatal("establishment rejected")
	}
	fseid, err := response.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	assoc := conn.associationByID("inactive.example")
	session := assoc.Sessions[fseid.SEID]
	if (local > 0 || timer > 0) && (session.activity == nil || plane.uplinkPDR.ActivitySlot == 0) {
		t.Fatal("PDR did not bind activity counter")
	}
	return conn, assoc, session, plane, peer
}
func inactivityUpdate(t *testing.T, conn *PfcpConnection, session *Session, peer *net.UDPConn, sequence uint32, timer *ie.IE, extra ...*ie.IE) {
	t.Helper()
	fields := append([]*ie.IE{timer}, extra...)
	conn.Handle(protocolWire(t, message.NewSessionModificationRequest(session.LocalSEID, sequence, fields...)), peer.LocalAddr().(*net.UDPAddr))
	if pipelineCause(t, identityRead(t, peer)) != 1 {
		t.Fatal("timer update rejected")
	}
}
func inactivityReport(t *testing.T, conn *PfcpConnection, session *Session, peer *net.UDPConn) *message.SessionReportRequest {
	t.Helper()
	report := identityRead(t, peer).(*message.SessionReportRequest)
	if !report.ReportType.HasUPIR() || report.PFCPSRReqFlags.HasPSDBU() || report.SEID() != session.RemoteSEID {
		t.Fatal("wrong inactivity report")
	}
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(session.LocalSEID, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
	return report
}
func TestInactivityUPIRStopsUntilTimerUpdated(t *testing.T) {
	conn, assoc, session, plane, peer := inactivityFixture(t, 2*time.Second, 0)
	session.activity.last = time.Now().Add(-3 * time.Second)
	conn.nextActivityPoll = time.Time{}
	conn.serviceInactivity(time.Now())
	inactivityReport(t, conn, session, peer)
	if session.inactivityArmed || assoc.Sessions[session.LocalSEID] != session || !plane.active {
		t.Fatal("UPIR removed live session or kept timer armed")
	}
	conn.nextActivityPoll = time.Time{}
	conn.serviceInactivity(time.Now().Add(30 * time.Second))
	if pipelineRead(t, peer, 10*time.Millisecond) != nil {
		t.Fatal("UPIR repeated without update")
	}
	inactivityUpdate(t, conn, session, peer, 3, ie.NewUserPlaneInactivityTimer(time.Second))
	inactivityReport(t, conn, session, peer)
}
func TestInactivityActivityAndUpdatedDeadline(t *testing.T) {
	conn, assoc, session, plane, peer := inactivityFixture(t, 10*time.Second, 0)
	session.activity.last = time.Now().Add(-5 * time.Second)
	// Increasing the timer preserves the actual last activity instead of rearming
	// it from the update; decreasing below elapsed time reports immediately.
	inactivityUpdate(t, conn, session, peer, 3, ie.NewUserPlaneInactivityTimer(20*time.Second))
	if pipelineRead(t, peer, 10*time.Millisecond) != nil {
		t.Fatal("longer timer reported early")
	}
	inactivityUpdate(t, conn, session, peer, 4, ie.NewUserPlaneInactivityTimer(2*time.Second))
	session = assoc.Sessions[session.LocalSEID]
	inactivityReport(t, conn, session, peer)
	plane.count++
	inactivityUpdate(t, conn, session, peer, 5, ie.NewUserPlaneInactivityTimer(time.Second))
	session = assoc.Sessions[session.LocalSEID]
	if !session.inactivityArmed || time.Since(session.activity.last) > time.Second {
		t.Fatal("received packet did not refresh inactivity")
	}
	if pipelineRead(t, peer, 10*time.Millisecond) != nil {
		t.Fatal("activity timer expired early")
	}
	session.activity.last = time.Now().Add(-2 * time.Second)
	inactivityUpdate(t, conn, session, peer, 6, ie.NewUserPlaneInactivityTimer(0))
	session = assoc.Sessions[session.LocalSEID]
	if session.inactivityArmed || pipelineRead(t, peer, 10*time.Millisecond) != nil {
		t.Fatal("zero timer did not disable reporting")
	}
	inactivityUpdate(t, conn, session, peer, 7, ie.New(ie.UserPlaneInactivityTimer, nil))
	if pipelineRead(t, peer, 10*time.Millisecond) != nil {
		t.Fatal("null timer did not disable reporting")
	}
}
func TestInactivityLocalReleaseUsesSameActivityAndDeletion(t *testing.T) {
	for _, cpTimer := range []time.Duration{0, time.Second} {
		t.Run(cpTimer.String(), func(t *testing.T) {
			conn, assoc, session, plane, peer := inactivityFixture(t, cpTimer, time.Second)
			session.activity.last = time.Now().Add(-2 * time.Second)
			plane.count++
			conn.nextActivityPoll = time.Time{}
			conn.serviceInactivity(time.Now())
			if assoc.Sessions[session.LocalSEID] == nil {
				t.Fatal("activity ignored by local release")
			}
			session.activity.last = time.Now().Add(-2 * time.Second)
			conn.nextActivityPoll = time.Time{}
			conn.serviceInactivity(time.Now())
			conn.serviceLocalSessionReleases()
			report := identityRead(t, peer).(*message.SessionReportRequest)
			if !report.ReportType.HasUISR() || !report.PFCPSRReqFlags.HasPSDBU() || report.ReportType.HasUPIR() || len(assoc.Sessions) != 0 || len(plane.released) != 1 {
				t.Fatal("local inactivity did not use common release")
			}
			conn.Handle(protocolWire(t, message.NewSessionReportResponse(session.LocalSEID, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
		})
	}
}
func TestInactivityFailedModificationAndReadFailure(t *testing.T) {
	conn, assoc, session, plane, peer := inactivityFixture(t, 0, 0)
	plane.failBegin = true
	request := message.NewSessionModificationRequest(session.LocalSEID, 3, ie.NewUserPlaneInactivityTimer(time.Second), ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(1)))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	if pipelineCause(t, identityRead(t, peer)) == 1 || assoc.Sessions[session.LocalSEID].activity != nil || plane.active || len(plane.released) != 1 {
		t.Fatal("failed modification leaked activity reservation")
	}
	plane.failBegin = false
	inactivityUpdate(t, conn, session, peer, 4, ie.NewUserPlaneInactivityTimer(time.Second))
	session = assoc.Sessions[session.LocalSEID]
	if plane.uplinkPDR.ActivitySlot == 0 {
		t.Fatal("existing PDR not rebound for monitoring")
	}
	plane.failRead = true
	conn.nextActivityPoll = time.Time{}
	conn.serviceInactivity(time.Now().Add(time.Hour))
	if conn.FatalError() == nil || assoc.Sessions[session.LocalSEID] == nil {
		t.Fatal("counter failure falsely deleted session")
	}
}
func TestPerPDRInactivityRemainsUnsupported(t *testing.T) {
	conn, _, session, _, peer := inactivityFixture(t, 0, 0)
	request := message.NewSessionModificationRequest(session.LocalSEID, 3, ie.NewCreateURR(ie.NewURRID(9), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0, 0, 0), ie.NewUserPlaneInactivityTimer(time.Second)))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.SessionModificationResponse)
	if pipelineCause(t, response) != ie.CauseServiceNotSupported || response.OffendingIE == nil || ie.NewUPFunctionFeatures(conn.featuresOctets...).HasUPIDP() {
		t.Fatal("per-PDR inactivity incorrectly admitted or advertised")
	}
}

func TestInactivityFailedUpdatePreservesLiveTimer(t *testing.T) {
	conn, assoc, session, plane, peer := inactivityFixture(t, 10*time.Second, 0)
	plane.failBegin = true
	conn.Handle(protocolWire(t, message.NewSessionModificationRequest(session.LocalSEID, 3, ie.NewUserPlaneInactivityTimer(0))), peer.LocalAddr().(*net.UDPAddr))
	if pipelineCause(t, identityRead(t, peer)) == 1 || assoc.Sessions[session.LocalSEID].inactivityTimer != 10*time.Second || !assoc.Sessions[session.LocalSEID].inactivityArmed || len(plane.released) != 0 {
		t.Fatal("failed update changed live timer or freed its counter")
	}
	plane.failBegin = false
}

type delayedActivityPlane struct {
	delayedUsagePlane
	activity *activityPlane
}

func (p *delayedActivityPlane) NewSessionActivity() (uint32, uint64, error) {
	return p.activity.NewSessionActivity()
}
func (p *delayedActivityPlane) SessionActivityCount(slot uint32) (uint64, error) {
	return p.activity.SessionActivityCount(slot)
}
func (p *delayedActivityPlane) ReleaseSessionActivity(slot uint32) {
	p.activity.ReleaseSessionActivity(slot)
}
func TestInactivityCounterReclamationWaitsForRuleGrace(t *testing.T) {
	conn, assoc, session, activity, peer := inactivityFixture(t, time.Second, 0)
	plane := &delayedActivityPlane{activity: activity}
	conn.mapOperations = plane
	session.NewUrr(9, 1, ebpf.UrrInfo{})
	if _, err := conn.ReleaseSessionByID(session.LocalSEID); err != nil {
		t.Fatal(err)
	}
	if len(activity.released) != 0 || !activity.active || assoc.Sessions[session.LocalSEID] != nil {
		t.Fatal("counter slot returned before reclamation")
	}
	plane.transaction.finish(t)
	if len(activity.released) != 1 || activity.active {
		t.Fatal("counter slot retained after reclamation")
	}
	conn.serviceLocalSessionReleases()
	report := identityRead(t, peer).(*message.SessionReportRequest)
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(session.LocalSEID, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
	if len(activity.released) != 1 {
		t.Fatal("response returned counter slot twice")
	}
}
