package ebpf

import (
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
