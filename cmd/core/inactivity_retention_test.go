package core

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestRetainedSessionInactivityDuringSampling(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		name := "control"
		if overlap {
			name = "setup_during_sample"
		}
		t.Run(name, func(t *testing.T) {
			conn, _, session, plane, peer := inactivityFixture(t, 2*time.Second, 0)
			controller := &delayedActivityController{SessionActivityController: plane, entered: make(chan struct{}), resume: make(chan struct{})}
			unblock := sync.OnceFunc(func() { close(controller.resume) })
			session.activity.controller = controller
			setup := func() {
				conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(900, newIeNodeID("inactive.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)), ie.NewPFCPSessionRetentionInformation())), peer.LocalAddr().(*net.UDPAddr))
				response := identityRead(t, peer).(*message.AssociationSetupResponse)
				if !response.PFCPASRspFlags.HasPSREI() {
					t.Fatal("session not retained")
				}
			}
			conn.stateMu.Lock()
			forceInactivityPoll(conn)
			conn.stateMu.Unlock()
			done := make(chan struct{})
			go func() { conn.serviceInactivity(time.Now()); close(done) }()
			t.Cleanup(func() { unblock(); <-done })
			<-controller.entered
			if overlap {
				setup()
			}
			unblock()
			<-done
			if !overlap {
				setup()
			}
			conn.stateMu.Lock()
			current := conn.associationByID("inactive.example").Sessions[session.LocalSEID]
			if current == nil || current.activity != session.activity {
				conn.stateMu.Unlock()
				t.Fatal("session not retained with its activity")
			}
			_, dirty := conn.activityDirty[session.LocalSEID]
			queued := current.activity.queued
			current.activity.last = time.Now().Add(-time.Hour)
			current.activity.due = time.Now().Add(-time.Second)
			conn.stateMu.Unlock()
			t.Logf("%s: queued=%v dirty=%v heap_len=%d", name, queued, dirty, len(conn.activityQueue))
			// TS 29.244 V20.1.0 clause 5.11.2: expiry remains within
			// the documented 2I + one worker tick after the deadline.
			now := time.Now()
			bound := 2*activityObservationInterval(current.inactivityTimer) + activityPollInterval
			for delay := time.Duration(0); delay <= bound; delay += activityPollInterval {
				conn.serviceInactivity(now.Add(delay))
			}
			report := pipelineRead(t, peer, 300*time.Millisecond)
			if report == nil {
				t.Errorf("%s: no UPIR for a session inactive for an hour with a 2 s timer", name)
				return
			}
			if r, ok := report.(*message.SessionReportRequest); !ok || !r.ReportType.HasUPIR() {
				t.Errorf("%s: unexpected message %T", name, report)
			}
		})
	}
}

func TestRemovedAssociationDiscardsInflightActivity(t *testing.T) {
	for _, reason := range []string{"release", "restart"} {
		t.Run(reason, func(t *testing.T) {
			conn, assoc, session, plane, peer := inactivityFixture(t, 2*time.Second, 0)
			controller := &delayedActivityController{SessionActivityController: plane, entered: make(chan struct{}), resume: make(chan struct{})}
			session.activity.controller = controller
			session.activity.last = time.Now().Add(-time.Hour)
			unblock := sync.OnceFunc(func() { close(controller.resume) })
			forceInactivityPoll(conn)
			done := make(chan struct{})
			go func() { conn.serviceInactivity(time.Now()); close(done) }()
			t.Cleanup(func() { unblock(); <-done })
			<-controller.entered
			conn.stateMu.Lock()
			if reason == "release" {
				conn.deleteAssociation(assoc.ID)
				conn.cleanupAssociationLocked(assoc, time.Now())
			} else {
				conn.observeEntityRecovery(assoc.ID, assoc.Addr, time.Unix(1700000000, 0))
				conn.observeEntityRecovery(assoc.ID, assoc.Addr, time.Unix(1700000010, 0))
			}
			conn.stateMu.Unlock()
			unblock()
			<-done
			conn.stateMu.Lock()
			_, indexed := conn.activitySessions[session.LocalSEID]
			queued, sampling := session.activity.queued, session.activity.sampling
			conn.stateMu.Unlock()
			if indexed || queued || sampling {
				t.Fatal("removed lifetime stayed on inactivity schedule")
			}
			if pipelineRead(t, peer, 20*time.Millisecond) != nil {
				t.Fatal("removed lifetime generated UPIR")
			}
			if conn.FatalError() != nil {
				t.Fatal(conn.FatalError())
			}
		})
	}
}

func TestRetainedSessionLocalReleaseDuringSampling(t *testing.T) {
	conn, _, session, plane, peer := inactivityFixture(t, 0, 2*time.Second)
	controller := &delayedActivityController{SessionActivityController: plane, entered: make(chan struct{}), resume: make(chan struct{})}
	session.activity.controller = controller
	session.activity.last = time.Now().Add(-time.Hour)
	unblock := sync.OnceFunc(func() { close(controller.resume) })
	forceInactivityPoll(conn)
	done := make(chan struct{})
	go func() { conn.serviceInactivity(time.Now()); close(done) }()
	t.Cleanup(func() { unblock(); <-done })
	<-controller.entered
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(900, newIeNodeID("inactive.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)), ie.NewPFCPSessionRetentionInformation())), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.AssociationSetupResponse)
	if !response.PFCPASRspFlags.HasPSREI() {
		t.Fatal("session not retained")
	}
	unblock()
	<-done
	conn.stateMu.Lock()
	current := conn.associationByID("inactive.example")
	remains := current.Sessions[session.LocalSEID] != nil
	conn.stateMu.Unlock()
	if remains {
		t.Fatal("retained session skipped local inactivity release")
	}
}
