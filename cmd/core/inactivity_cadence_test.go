package core

import (
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestInactivityObservationCadenceFollowsSessionTimer(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "cp", true: "local"}[local], func(t *testing.T) {
			cpTimer, localTimer := 24*time.Hour, time.Duration(0)
			if local {
				cpTimer, localTimer = 0, 24*time.Hour
			}
			conn, _, session, plane, _ := inactivityFixture(t, cpTimer, localTimer)
			controller := &countedActivityController{SessionActivityController: plane}
			session.activity.controller = controller
			now := time.Now()
			for i := 1; i <= 40; i++ {
				for conn.serviceInactivity(now.Add(time.Duration(i) * 100 * time.Millisecond)) {
				}
			}
			if controller.reads != 0 {
				t.Fatalf("day-long timer sampled %d times in four seconds", controller.reads)
			}
			for conn.serviceInactivity(now.Add(6 * time.Second)) {
			}
			if controller.reads != 1 {
				t.Fatalf("due observation count=%d want 1", controller.reads)
			}
		})
	}
}

func TestInactivityTimerUpdateWaitsForObservationAfterProvisioning(t *testing.T) {
	conn, assoc, session, plane, peer := inactivityFixture(t, 10*time.Second, 0)
	session.activity.last = time.Now().Add(-2 * time.Second)
	controller := &delayedEmptyActivityController{SessionActivityController: plane, entered: make(chan struct{}), resume: make(chan struct{})}
	session.activity.controller = controller
	forceInactivityPoll(conn)
	done := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(controller.resume) })
	go func() { conn.serviceInactivity(time.Now()); close(done) }()
	t.Cleanup(func() { unblock(); <-done })
	<-controller.entered
	conn.stateMu.Lock()
	plane.count = 1
	conn.stateMu.Unlock()
	inactivityUpdate(t, conn, session, peer, 20, ie.NewUserPlaneInactivityTimer(time.Second))
	unblock()
	<-done
	if report := pipelineRead(t, peer, 10*time.Millisecond); report != nil {
		t.Fatal("observation preceding the timer update expired across a later packet")
	}
	conn.serviceInactivity(time.Now())
	current := assoc.Sessions[session.LocalSEID]
	if !current.inactivityArmed || time.Since(current.activity.last) > time.Second {
		t.Fatal("fresh observation lost the packet before the timer update")
	}
}

func TestInactivityObservationIntervalBounds(t *testing.T) {
	for _, tc := range []struct{ timer, interval time.Duration }{{0, 0}, {-time.Second, 0}, {time.Nanosecond, 100 * time.Millisecond}, {time.Second, 100 * time.Millisecond}, {4 * time.Second, 100 * time.Millisecond}, {40 * time.Second, time.Second}, {200 * time.Second, 5 * time.Second}, {24 * time.Hour, 5 * time.Second}} {
		if got := activityObservationInterval(tc.timer); got != tc.interval {
			t.Fatalf("timer=%s interval=%s want %s", tc.timer, got, tc.interval)
		}
	}
}
func TestInactivityDisablingTimerStopsScheduledObservations(t *testing.T) {
	conn, assoc, session, plane, peer := inactivityFixture(t, time.Hour, 0)
	inactivityUpdate(t, conn, session, peer, 30, ie.NewUserPlaneInactivityTimer(0))
	session = assoc.Sessions[session.LocalSEID]
	controller := &countedActivityController{SessionActivityController: plane}
	session.activity.controller = controller
	inactivityUpdate(t, conn, session, peer, 31, nil, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewTransportLevelMarking([]byte{0x10, 0xfc}))))
	for conn.serviceInactivity(time.Now().Add(time.Hour)) {
	}
	if controller.reads != 0 || len(conn.activityQueue) != 0 {
		t.Fatal("disabled timer remained in scheduled observations")
	}
}
