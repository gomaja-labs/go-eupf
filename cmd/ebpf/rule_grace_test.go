package ebpf

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuleGraceBatchesRetirementsAfterReadersFinish(t *testing.T) {
	entered := make(chan struct{})
	secondEntered := make(chan struct{})
	secondRelease := make(chan struct{})
	var secondOnce sync.Once
	release := make(chan struct{})
	var once sync.Once
	var calls, reclaimed atomic.Int32
	g := &ruleGrace{wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	g.synchronize = func() error {
		switch calls.Add(1) {
		case 1:
			close(entered)
			<-release
		case 2:
			close(secondEntered)
			<-secondRelease
		}
		return nil
	}
	go g.run()
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		secondOnce.Do(func() { close(secondRelease) })
		close(g.stop)
		<-g.done
	})
	g.enqueue(graceWork{})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("grace period did not start")
	}
	for range 1000 {
		g.retire([]func() error{func() error { reclaimed.Add(1); return nil }}, false)
	}
	done := make(chan error, 1)
	g.enqueue(graceWork{done: done})
	if got := reclaimed.Load(); got != 0 {
		t.Fatalf("reclaimed before old readers returned: %d", got)
	}
	once.Do(func() { close(release) })
	select {
	case <-secondEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("batched grace period did not start")
	}
	if got := reclaimed.Load(); got != 0 {
		t.Fatalf("reclaimed before batched readers returned: %d", got)
	}
	secondOnce.Do(func() { close(secondRelease) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reclamation did not finish")
	}
	if got := reclaimed.Load(); got != 1000 {
		t.Fatalf("reclaimed=%d", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("1000 retirements used %d grace periods, want two including initial reader", got)
	}
}

func TestRuleRecoveryRetriesWithBackoff(t *testing.T) {
	g := &ruleGrace{failures: make(chan error, 1)}
	g.synchronize = func() error { return nil }
	attempts := []time.Time{}
	done := make(chan error, 1)
	g.enqueue(graceWork{sessionID: 17, done: done, reclaim: func() error {
		attempts = append(attempts, time.Now())
		if len(attempts) < 3 {
			return fmt.Errorf("synthetic reclaim failure")
		}
		return nil
	}})
	g.drain()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 3 || attempts[1].Sub(attempts[0]) < 100*time.Millisecond || attempts[2].Sub(attempts[1]) < 200*time.Millisecond {
		t.Fatal("recovery omitted bounded exponential backoff")
	}
	if g.failure() != nil {
		t.Fatal("successful recovery poisoned admission")
	}
}

func TestExhaustedRuleRecoveryNotifiesSupervisorWithoutReclaiming(t *testing.T) {
	g := &ruleGrace{failures: make(chan error, 1)}
	g.synchronize = func() error { return fmt.Errorf("synthetic grace failure") }
	reclaimed := false
	done := make(chan error, 1)
	g.enqueue(graceWork{sessionID: 17, failedAt: time.Now().Add(-ruleRecoveryWindow), done: done, reclaim: func() error { reclaimed = true; return nil }})
	g.drain()
	if err := <-done; err == nil {
		t.Fatal("waiting response did not receive terminal failure")
	}
	if reclaimed || g.failure() == nil {
		t.Fatal("failed grace released identifiers or hid fatal failure")
	}
	select {
	case err := <-g.failures:
		if err == nil {
			t.Fatal("nil supervisor error")
		}
	default:
		t.Fatal("supervisor was not notified")
	}
}

func TestAfterRuleGraceDoesNotRunBeforeOldReadersFinish(t *testing.T) {
	entered, release, completed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	g := &ruleGrace{wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	g.synchronize = func() error { close(entered); <-release; return nil }
	b := &BpfObjects{grace: g}
	go g.run()
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); close(g.stop); <-g.done })
	if err := b.AfterRuleGrace(func() error { close(completed); return nil }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("grace period did not start")
	}
	select {
	case <-completed:
		t.Fatal("callback ran with old readers still active")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("callback did not run after grace period")
	}
	b.ruleClosed = true
	if err := b.AfterRuleGrace(func() error { return nil }); err == nil {
		t.Fatal("closed map lifetime admitted callback")
	}
}
