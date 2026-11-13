package service

import (
	"fmt"
	"sync"
	"testing"
)

func TestReplayReservationsCannotOverbookConcurrentEndpoints(t *testing.T) {
	var budget ReplayBudget
	var done sync.WaitGroup
	const attempts = 128
	results := make(chan bool, attempts)
	release := make(chan struct{})
	for n := range attempts {
		done.Add(1)
		go func() {
			defer done.Done()
			owner := fmt.Sprint(n)
			ok := budget.Reserve(owner, 65536, 64, 64*65536)
			results <- ok
			<-release
			if ok {
				budget.Change(owner, -1, -65536)
			}
		}()
	}
	accepted := 0
	for range attempts {
		if <-results {
			accepted++
		}
	}
	close(release)
	done.Wait()
	if accepted != 64 || budget.entries != 0 || budget.bytes != 0 || len(budget.owners) != 0 {
		t.Fatalf("accepted %d remaining %d bytes %d owners %d", accepted, budget.entries, budget.bytes, len(budget.owners))
	}
}

func TestReplayFairSharesIncludeEveryEndpoint(t *testing.T) {
	var budget ReplayBudget
	for range 4 {
		if !budget.Reserve("heavy", 1024, 12, 1<<20) {
			t.Fatal("initial share denied")
		}
	}
	if !budget.Reserve("light", 1024, 12, 1<<20) {
		t.Fatal("new association denied available capacity")
	}
	for range 2 {
		if !budget.Reserve("heavy", 1024, 12, 1<<20) {
			t.Fatal("heavy association denied its share")
		}
	}
	if budget.Reserve("heavy", 1024, 12, 1<<20) {
		t.Fatal("heavy association exceeded its shared fair share")
	}
	if !budget.Reserve("later", 1024, 12, 1<<20) {
		t.Fatal("later endpoint denied available capacity")
	}
	if budget.Reserve("heavy", 1024, 12, 1<<20) {
		t.Fatal("new endpoint failed to reduce the heavy association's share")
	}
	if !budget.Reserve("light", 1024, 12, 1<<20) {
		t.Fatal("below-share association denied available capacity")
	}
}
