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
			owner := ReplayOwner{Endpoint: 1, NodeID: fmt.Sprint(n)}
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
		if !budget.Reserve(ReplayOwner{Endpoint: 1, NodeID: "heavy"}, 1024, 12, 1<<20) {
			t.Fatal("initial share denied")
		}
	}
	if !budget.Reserve(ReplayOwner{Endpoint: 2, NodeID: "light"}, 1024, 12, 1<<20) {
		t.Fatal("new association denied available capacity")
	}
	for range 2 {
		if !budget.Reserve(ReplayOwner{Endpoint: 1, NodeID: "heavy"}, 1024, 12, 1<<20) {
			t.Fatal("heavy association denied its share")
		}
	}
	if budget.Reserve(ReplayOwner{Endpoint: 1, NodeID: "heavy"}, 1024, 12, 1<<20) {
		t.Fatal("heavy association exceeded its shared fair share")
	}
	if !budget.Reserve(ReplayOwner{Endpoint: 3, NodeID: "later"}, 1024, 12, 1<<20) {
		t.Fatal("later endpoint denied available capacity")
	}
	if budget.Reserve(ReplayOwner{Endpoint: 1, NodeID: "heavy"}, 1024, 12, 1<<20) {
		t.Fatal("new endpoint failed to reduce the heavy association's share")
	}
	if !budget.Reserve(ReplayOwner{Endpoint: 2, NodeID: "light"}, 1024, 12, 1<<20) {
		t.Fatal("below-share association denied available capacity")
	}
}

func TestReplayEndpointIdentitiesNeverWrap(t *testing.T) {
	var budget ReplayBudget
	if budget.NewEndpoint() != 1 || budget.NewEndpoint() != 2 {
		t.Fatal("endpoint identities collided")
	}
	budget.nextEndpoint = ^uint64(0) - 1
	if budget.NewEndpoint() != ^uint64(0) || budget.NewEndpoint() != 0 || budget.NewEndpoint() != 0 {
		t.Fatal("exhausted endpoint identities wrapped")
	}
}
