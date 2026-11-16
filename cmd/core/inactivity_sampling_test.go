package core

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

type delayedActivityController struct {
	ebpf.SessionActivityController
	entered, resume chan struct{}
	reads           atomic.Int32
}

func (p *delayedActivityController) ConsumeSessionActivity(slot uint32) (bool, error) {
	if p.reads.Add(1) == 1 {
		close(p.entered)
		<-p.resume
	}
	return p.SessionActivityController.ConsumeSessionActivity(slot)
}

func TestInactivityPendingObservationCannotBeOvertaken(t *testing.T) {
	conn := &PfcpConnection{done: make(chan struct{})}
	assoc := NewNodeAssociation("sample.example", "127.0.0.1")
	plane := &activityPlane{MapOperationsMock: &MapOperationsMock{}, count: 1}
	controller := &delayedActivityController{SessionActivityController: plane, entered: make(chan struct{}), resume: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(controller.resume) })
	session := NewSession(1, 2, "", "", false)
	session.activity = &sessionActivity{controller: controller, slot: 1, last: time.Now().Add(-time.Hour)}
	assoc.Sessions[session.LocalSEID] = session
	conn.watchSessionActivity(assoc, session, 1)
	finished := make(chan struct{})
	go func() { conn.serviceInactivity(time.Now()); close(finished) }()
	t.Cleanup(func() { unblock(); <-finished })
	<-controller.entered
	conn.serviceInactivity(time.Now())
	if controller.reads.Load() != 1 {
		t.Fatal("a second observation overtook pending packet activity")
	}
	unblock()
	<-finished
	if time.Since(session.activity.last) > time.Second {
		t.Fatal("the pending positive observation was lost")
	}
}

func TestInactivitySamplerPinsSlotAndAdmissionThroughGrace(t *testing.T) {
	conn, assoc, session, activity, _ := inactivityFixture(t, time.Second, 0)
	plane := &delayedActivityPlane{activity: activity}
	conn.mapOperations = plane
	session.NewUrr(9, 1, ebpf.UrrInfo{})
	controller := &delayedActivityController{SessionActivityController: activity, entered: make(chan struct{}), resume: make(chan struct{})}
	session.activity.controller = controller
	unblock := sync.OnceFunc(func() { close(controller.resume) })
	for id := uint64(100); id < 115; id++ {
		if err := conn.ResourceManager.AdmitSession(id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.ResourceManager.ReleaseSession(id) })
	}
	conn.nextActivityPoll = time.Time{}
	finished := make(chan struct{})
	go func() { conn.serviceInactivity(time.Now()); close(finished) }()
	t.Cleanup(func() { unblock(); <-finished })
	<-controller.entered
	if _, err := conn.ReleaseSessionByID(session.LocalSEID); err != nil {
		t.Fatal(err)
	}
	plane.transaction.finish(t)
	if len(activity.released) != 0 || !activity.active || assoc.Sessions[session.LocalSEID] != nil {
		t.Fatal("sampler slot returned before its observation completed")
	}
	if err := conn.ResourceManager.AdmitSession(200); !errors.Is(err, service.ErrResourceExhausted) {
		t.Fatal("sampler pin lost the admission reservation", err)
	}
	// A late read failure from a deleted context cannot delete another lifetime
	// or become an activity failure for an unrelated active session.
	activity.failRead = true
	unblock()
	<-finished
	if len(activity.released) != 1 || activity.active || conn.FatalError() != nil {
		t.Fatal("completed sampler retained or corrupted a retired lifetime")
	}
	if err := conn.ResourceManager.AdmitSession(200); err != nil {
		t.Fatal("sampler completion did not return admission", err)
	}
	conn.ResourceManager.ReleaseSession(200)
}

func TestInactivityUpdatedSessionPrecedesBulkDirtyEntries(t *testing.T) {
	conn := &PfcpConnection{done: make(chan struct{})}
	assoc := NewNodeAssociation("sample.example", "127.0.0.1")
	plane := &sampledActivityPlane{reads: make(map[uint32]int)}
	for id := uint32(1); id <= 1024; id++ {
		session := NewSession(uint64(id), uint64(id), "", "", false)
		session.activity = &sessionActivity{controller: plane, slot: id, last: time.Now()}
		assoc.Sessions[session.LocalSEID] = session
		conn.watchSessionActivity(assoc, session, 1)
	}
	conn.serviceInactivityUpdates(time.Now(), 1024)
	if plane.reads[1024] != 1 || len(plane.reads) > 64 {
		t.Fatal("updated timer waited behind unrelated dirty sessions")
	}
}

func TestInactivityRunPollsWithoutDatagrams(t *testing.T) {
	conn, _, session, _, peer := inactivityFixture(t, time.Second, 0)
	session.activity.last = time.Now().Add(-2 * time.Second)
	finished := make(chan struct{})
	go func() { conn.Run(); close(finished) }()
	t.Cleanup(func() {
		conn.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("receive loop did not stop")
		}
	})
	inactivityReport(t, conn, session, peer)
}
