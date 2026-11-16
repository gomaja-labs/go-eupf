package ebpf

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func blockedRuleRetirement(t *testing.T) (*ruleGrace, <-chan struct{}, func()) {
	t.Helper()
	entered, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	signal := sync.OnceFunc(func() { close(entered) })
	g := &ruleGrace{wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	g.synchronize = func() error { signal(); <-resume; return nil }
	go g.run()
	t.Cleanup(func() { unblock(); close(g.stop); <-g.done })
	return g, entered, unblock
}

func TestRuleVersionCapacityWaitsForRetiredSlots(t *testing.T) {
	for _, kind := range []string{"FAR", "QER", "URR"} {
		t.Run(kind, func(t *testing.T) {
			b := NewBpfObjects()
			b.farIdTracker, b.qerIdTracker, b.urrIdTracker = NewIdTracker(2), NewIdTracker(2), NewIdTracker(2)
			var allocate func() (uint32, error)
			var release func(uint32)
			switch kind {
			case "FAR":
				allocate, release = b.GetNextFAR, b.ReleaseFAR
			case "QER":
				allocate, release = b.GetNextQER, b.ReleaseQER
			case "URR":
				allocate, release = b.GetNextURR, b.ReleaseURR
			}
			id, err := allocate()
			if err != nil {
				t.Fatal(err)
			}
			g, entered, unblock := blockedRuleRetirement(t)
			b.grace = g
			g.retire([]func() error{func() error { release(id); return nil }}, false)
			<-entered
			result := make(chan error, 1)
			go func() {
				next, err := allocate()
				if err == nil && next != id {
					err = errors.New("retired slot was not reused")
				}
				result <- err
			}()
			select {
			case err := <-result:
				t.Fatalf("capacity rejected before retirement: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
			unblock()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("retired capacity did not wake the request")
			}
		})
	}
}

func TestPDRBucketCapacityHasBoundedRetirementWait(t *testing.T) {
	b := NewBpfObjects()
	b.bucketIDs = NewIdTracker(1)
	g, _, unblock := blockedRuleRetirement(t)
	b.grace = g
	tx := &ruleTransaction{objects: b}
	result := make(chan error, 1)
	go func() { _, err := tx.allocateBucket(); result <- err }()
	select {
	case err := <-result:
		if !errors.Is(err, ErrRuleCapacity) {
			t.Fatalf("exhaustion lost its resource cause: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		unblock()
		if err := <-result; err != nil && !errors.Is(err, ErrRuleCapacity) {
			t.Error(err)
		}
		t.Fatal("bucket allocation waited beyond the retirement bound")
	}
}
