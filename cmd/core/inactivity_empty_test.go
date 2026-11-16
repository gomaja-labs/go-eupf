package core

import (
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

type delayedEmptyActivityController struct {
	ebpf.SessionActivityController
	entered, resume chan struct{}
	first           bool
}

func (controller *delayedEmptyActivityController) ConsumeSessionActivity(slot uint32) (bool, error) {
	active, err := controller.SessionActivityController.ConsumeSessionActivity(slot)
	if !controller.first {
		controller.first = true
		close(controller.entered)
		<-controller.resume
	}
	return active, err
}

func TestInactivityEmptyObservationCannotExpireAcrossLaterPacket(t *testing.T) {
	conn, _, session, activity, _ := inactivityFixture(t, time.Second, 0)
	controller := &delayedEmptyActivityController{SessionActivityController: activity, entered: make(chan struct{}), resume: make(chan struct{})}
	session.activity.controller = controller
	conn.nextActivityPoll = time.Time{}
	unblock := sync.OnceFunc(func() { close(controller.resume) })
	done := make(chan struct{})
	go func() { conn.serviceInactivity(time.Now()); close(done) }()
	t.Cleanup(func() { unblock(); <-done })
	<-controller.entered
	// The empty value has been read. A packet arrives before the old deadline,
	// while completion of that read is held beyond it.
	conn.stateMu.Lock()
	session.activity.last = time.Now().Add(-900 * time.Millisecond)
	activity.count = 1
	conn.stateMu.Unlock()
	time.Sleep(150 * time.Millisecond)
	unblock()
	<-done
	if !session.inactivityArmed {
		t.Fatal("empty observation expired after a later packet had arrived before its deadline")
	}
	conn.nextActivityPoll = time.Time{}
	conn.serviceInactivity(time.Now())
	if !session.inactivityArmed || time.Since(session.activity.last) > time.Second {
		t.Fatal("next observation lost the packet that followed the empty read")
	}
}
