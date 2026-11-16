package ebpf

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCapacityWaitersShareOnePendingBarrier(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	signal := sync.OnceFunc(func() { close(entered) })
	unblock := sync.OnceFunc(func() { close(resume) })
	g := &ruleGrace{wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	g.synchronize = func() error { signal(); <-resume; return nil }
	go g.run()
	t.Cleanup(func() { unblock(); close(g.stop); <-g.done })
	var wait sync.WaitGroup
	for range 32 {
		wait.Go(func() {
			if err := g.waitForCapacity(time.Now().Add(20 * time.Millisecond)); !errors.Is(err, ErrRuleCapacity) {
				t.Errorf("stalled barrier lost capacity error: %v", err)
			}
		})
	}
	<-entered
	wait.Wait()
	g.mu.Lock()
	pending, ready := len(g.pending), g.capacityReady
	g.mu.Unlock()
	if pending > 1 || ready == nil {
		t.Fatalf("timed-out requests retained separate barriers: pending=%d", pending)
	}
	unblock()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("late barrier completion stalled after every caller timed out")
	}
}

func TestCapacityWaitPreservesRecoveryFailureAndExpiredBudget(t *testing.T) {
	failure := errors.New("synthetic rule recovery failure")
	g := &ruleGrace{err: failure}
	if err := g.waitForCapacity(time.Now().Add(time.Second)); !errors.Is(err, failure) {
		t.Fatalf("recovery failure became resource exhaustion: %v", err)
	}
	g.err = nil
	if err := g.waitForCapacity(time.Now().Add(-time.Millisecond)); !errors.Is(err, ErrRuleCapacity) || len(g.pending) != 0 {
		t.Fatal("expired budget enqueued another barrier")
	}
}
