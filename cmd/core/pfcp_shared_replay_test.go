package core

import (
	"fmt"
	"testing"
)

func TestReplayFairShareAcrossAllPFCPConnections(t *testing.T) {
	first := newProtocolConnection(t)
	connections := []*PfcpConnection{first, newProtocolConnection(t), newProtocolConnection(t)}
	for _, conn := range connections {
		conn.ResourceManager = first.ResourceManager
		conn.maxReplayEntries = 96
	}
	// Forty-eight associations share one process budget, including associations
	// on Sxa and Sxb. Every association can retain its two-entry fair share.
	for round := 0; round < 2; round++ {
		for n := 0; n < 48; n++ {
			conn := connections[n%3]
			owner := fmt.Sprintf("cp-%d.example", n)
			key := requestKey{peer: fmt.Sprintf("127.1.0.%d:8805", n+1), sequence: uint32(round + 1), typ: 7}
			if _, found, err := conn.cachedReply(key, [32]byte{}, owner); found || err != nil {
				t.Fatalf("fair share denied to %s round %d: %v", owner, round, err)
			}
			conn.cacheReply(key, [32]byte{}, []byte{1}, owner, owner)
		}
	}
	for n, conn := range connections {
		if _, _, err := conn.cachedReply(requestKey{peer: "127.1.0.1:8805", sequence: 99, typ: 7}, [32]byte{}, fmt.Sprintf("new-%d.example", n)); err == nil {
			t.Fatal("one endpoint multiplied the process replay capacity")
		}
	}
	// Closing one endpoint releases only its share, and never destroys the
	// retained outcomes of either remaining endpoint.
	connections[0].Close()
	if len(connections[1].transport.responses) != 32 || len(connections[2].transport.responses) != 32 {
		t.Fatal("endpoint close removed another endpoint's replay outcomes")
	}
}

func TestSamePeerNodeHasSeparateAssociationSharesOnDifferentEndpoints(t *testing.T) {
	first := newProtocolConnection(t)
	second := newProtocolConnection(t)
	third := newProtocolConnection(t)
	for _, conn := range []*PfcpConnection{first, second, third} {
		conn.ResourceManager = first.ResourceManager
		conn.maxReplayEntries = 12
	}
	for n := range 6 {
		first.cacheReply(requestKey{peer: "198.18.0.1:8805", sequence: uint32(n), typ: 7}, [32]byte{}, []byte{1}, "198.18.0.1", "cp.example")
	}
	for n := range 2 {
		second.cacheReply(requestKey{peer: "198.18.0.2:8805", sequence: uint32(n), typ: 7}, [32]byte{}, []byte{1}, "198.18.0.2", "other.example")
	}
	if _, found, err := third.cachedReply(requestKey{peer: "198.18.0.1:8805", sequence: 100, typ: 7}, [32]byte{}, "cp.example"); found || err != nil {
		t.Fatal("another local endpoint's association inherited the heavy endpoint's share")
	}
	if _, _, err := first.cachedReply(requestKey{peer: "198.18.0.1:8805", sequence: 101, typ: 7}, [32]byte{}, "cp.example"); err == nil {
		t.Fatal("heavy association ignored the new endpoint's fair share")
	}
}
