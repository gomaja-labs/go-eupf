package core

import (
	"testing"
	"time"
)

type sampledActivityPlane struct{ reads map[uint32]int }

func (p *sampledActivityPlane) NewSessionActivity() (uint32, error) { return 0, nil }
func (p *sampledActivityPlane) ConsumeSessionActivity(slot uint32) (bool, error) {
	p.reads[slot]++
	return false, nil
}
func (p *sampledActivityPlane) ReleaseSessionActivity(uint32) {}

type completedActivityPlane struct {
	sampledActivityPlane
	completed time.Time
}

func (p *completedActivityPlane) ConsumeSessionActivity(uint32) (bool, error) {
	p.completed = time.Now()
	return true, nil
}

func TestInactivityObservationIsTimestampedAfterConsumption(t *testing.T) {
	conn := &PfcpConnection{done: make(chan struct{})}
	assoc := NewNodeAssociation("poll.example", "127.0.0.1")
	plane := &completedActivityPlane{}
	now := time.Now()
	session := NewSession(1, 2, "", "", false)
	session.activity = &sessionActivity{controller: plane, slot: 1, last: now.Add(-time.Hour)}
	assoc.Sessions[session.LocalSEID] = session
	conn.watchSessionActivity(assoc, session, 1)
	conn.serviceInactivity(now)
	if session.activity.last.Before(plane.completed) {
		t.Fatal("activity preceding the clear was timestamped too early")
	}
}

func TestInactivityPollBoundsEachBatchAndVisitsEverySession(t *testing.T) {
	conn := &PfcpConnection{done: make(chan struct{})}
	assoc := NewNodeAssociation("poll.example", "127.0.0.1")
	plane := &sampledActivityPlane{reads: make(map[uint32]int)}
	now := time.Now()
	for id := uint32(1); id <= 1024; id++ {
		session := NewSession(uint64(id), uint64(id), "", "", false)
		session.activity = &sessionActivity{controller: plane, slot: id, last: now}
		assoc.Sessions[session.LocalSEID] = session
		conn.watchSessionActivity(assoc, session, 1)
	}
	clear(conn.activityDirty)
	for range 16 {
		before := 0
		for _, count := range plane.reads {
			before += count
		}
		conn.serviceInactivity(now)
		after := 0
		for _, count := range plane.reads {
			after += count
		}
		if after-before > 64 {
			t.Fatalf("poll held state lock for %d sessions, limit 64", after-before)
		}
	}
	if len(plane.reads) != 1024 {
		t.Fatalf("poll starved sessions: observed %d of 1024", len(plane.reads))
	}
}

func TestInactivityDisabledDoesNotWaitForStateLock(t *testing.T) {
	conn := &PfcpConnection{done: make(chan struct{})}
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	finished := make(chan struct{})
	go func() {
		conn.serviceInactivity(time.Now())
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("disabled monitoring waited for state lock")
	}
}

func TestInactivityQueueTracksRemovalAndReplacement(t *testing.T) {
	conn := &PfcpConnection{done: make(chan struct{})}
	assoc := NewNodeAssociation("poll.example", "127.0.0.1")
	plane := &sampledActivityPlane{reads: make(map[uint32]int)}
	now := time.Now()
	for id := uint32(1); id <= 128; id++ {
		session := NewSession(uint64(id), uint64(id), "", "", false)
		session.activity = &sessionActivity{controller: plane, slot: id, last: now}
		assoc.Sessions[session.LocalSEID] = session
		conn.watchSessionActivity(assoc, session, 1)
	}
	clear(conn.activityDirty)
	conn.serviceInactivity(now)
	for id := uint64(1); id <= 128; id++ {
		before := assoc.Sessions[id]
		conn.watchSessionActivity(assoc, before, -1)
		if id%2 == 0 {
			after := cloneSession(before)
			assoc.Sessions[id] = after
			conn.watchSessionActivity(assoc, after, 1)
		} else {
			delete(assoc.Sessions, id)
		}
	}
	clear(conn.activityDirty)
	clear(plane.reads)
	conn.nextActivityPoll = time.Time{}
	for range 8 {
		conn.serviceInactivity(now)
	}
	if len(plane.reads) != 64 || conn.activityCount.Load() != 64 {
		t.Fatal("replacement or removal lost monitored sessions")
	}
	for id := range plane.reads {
		if id%2 != 0 {
			t.Fatal("retired session remained in polling queue")
		}
	}
	for _, session := range assoc.Sessions {
		conn.watchSessionActivity(assoc, session, -1)
	}
	if conn.activityHead != nil || conn.activityTail != nil || conn.activityCount.Load() != 0 {
		t.Fatal("activity queue retained removed sessions")
	}
}
