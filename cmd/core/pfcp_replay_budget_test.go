package core

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog"
)

func TestReplayCacheHasOneConnectionBudget(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxReplayEntries = 64
	old := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(old)
	for a := 0; a < 16; a++ {
		node := fmt.Sprintf("cp-%d.example", a)
		peer := &net.UDPAddr{IP: net.IPv4(127, 64, 0, byte(a+1)), Port: 40000}
		conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN(node), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))), peer)
	}
	if conn.GetAssiciationCount() != 16 {
		t.Fatal("stress fixture did not establish every association")
	}
	for a := 0; a < 16; a++ {
		node := fmt.Sprintf("cp-%d.example", a)
		peer := &net.UDPAddr{IP: net.IPv4(127, 64, 0, byte(a+1)), Port: 40000}
		for n := 0; n < 64; n++ {
			conn.Handle(protocolWire(t, message.NewAssociationUpdateRequest(uint32(n+2), ie.NewNodeIDFQDN(node))), peer)
		}
	}

	if got := len(conn.transport.responses); got > conn.transactionLimit() {
		t.Fatalf("connection cached %d outcomes, limit %d", got, conn.transactionLimit())
	}
	start := time.Now()
	conn.DeleteAllAssociations()
	t.Logf("release 16 associations at the global bound: %v", time.Since(start))
	if len(conn.transport.responses) != 0 || len(conn.transport.responseBudgets) != 0 {
		t.Fatal("association cleanup retained response accounting")
	}
}

func TestAssociationReleaseBypassesProtectedReplayCache(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxReplayEntries = 1
	peer := identityPeer(t, "127.0.0.2", 0)
	identitySetup(t, conn, peer, "cp.example")
	conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(2, ie.NewNodeIDFQDN("cp.example"))), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.AssociationReleaseResponse)
	if cause, _ := response.Cause.Cause(); cause != ie.CauseRequestAccepted || conn.GetAssiciationCount() != 0 {
		t.Fatal("protected cache blocked Release")
	}
}

func TestNegotiatedBundlesUseEveryDatagramBoundedFrame(t *testing.T) {
	for _, count := range []int{17, 32} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			conn := newProtocolConnection(t)
			peer := identityPeer(t, "127.0.0.2", 0)
			conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("cp.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewCPFunctionFeatures(0x10))), peer.LocalAddr().(*net.UDPAddr))
			_ = identityRead(t, peer)
			msgs := make([]message.Message, count)
			for i := range msgs {
				msgs[i] = message.NewSessionDeletionRequest(999, uint32(i+2), ie.New(4000, make([]byte, 300)))
			}
			wire, err := message.MarshalDatagram(msgs...)
			if err != nil {
				t.Fatal(err)
			}
			conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
			for range count {
				_ = identityRead(t, peer)
			}
		})
	}
}

func TestBundleRequiresFeaturesAdvertisedForThatAssociation(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.2", 0)
	identitySetup(t, conn, peer, "cp.example")
	assoc := conn.associationByID("cp.example")
	assoc.CPFeatures = []byte{0x10}
	assoc.UPFeatures = []byte{0, 0} // A UP-initiated Sxa Setup advertised no BUNDL.
	msgs := []message.Message{message.NewSessionDeletionRequest(99, 2), message.NewSessionDeletionRequest(99, 3)}
	wire, err := message.MarshalDatagram(msgs...)
	if err != nil {
		t.Fatal(err)
	}
	conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
	if got := isolationRead(t, peer, 20*time.Millisecond); got != nil {
		t.Fatal("connection features substituted for association negotiation")
	}
}

func TestReplayFairShareNeverEvictsUnexpiredOutcomes(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxReplayEntries = 4
	for i := range 3 {
		conn.cacheReply(requestKey{peer: "127.0.0.2:40000", sequence: uint32(i), typ: 7}, [32]byte{}, []byte{1}, "heavy", "heavy")
	}
	next := requestKey{peer: "127.0.0.3:50000", sequence: 20, typ: 7}
	if _, found, err := conn.cachedReply(next, [32]byte{}, "light"); err != nil || found {
		t.Fatal("below-share entrant denied available capacity")
	}
	conn.cacheReply(next, [32]byte{}, []byte{1}, "light", "light")
	created := conn.transport.responseExpiry.Front().created
	next.sequence++
	if _, _, err := conn.cachedReplyAt(next, [32]byte{}, created.Add(25*time.Second), "light"); err == nil {
		t.Fatal("evicted an unexpired outcome")
	}
	if len(conn.transport.responses) != 4 {
		t.Fatal("protected cache changed")
	}
	if _, found, err := conn.cachedReplyAt(next, [32]byte{}, created.Add(61*time.Second), "light"); found || err != nil {
		t.Fatal("expired entries blocked capacity")
	}
	conn.discardReply(next, [32]byte{}) // Release the newly admitted reservation.
	if len(conn.transport.responses) != 0 || conn.transport.bytes != 0 {
		t.Fatal("expiry leaked accounting")
	}
}

func TestReplayBudgetFollowsNodeAcrossSourceAddresses(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxReplayEntries = 4
	first := identityPeer(t, "127.0.0.2", 0)
	second := identityPeer(t, "127.0.0.4", 0)
	identitySetup(t, conn, first, "cp.example")
	for seq := uint32(2); seq <= 4; seq++ {
		conn.Handle(protocolWire(t, message.NewAssociationUpdateRequest(seq, ie.NewNodeIDFQDN("cp.example"))), second.LocalAddr().(*net.UDPAddr))
		_ = identityRead(t, second)
	}
	budget := conn.transport.responseBudgets["cp.example"]
	if len(conn.transport.responseBudgets) != 1 || budget == nil || budget.entries.Len() != 4 {
		t.Fatal("one association acquired multiple address budgets")
	}
	conn.Handle(protocolWire(t, message.NewAssociationUpdateRequest(5, ie.NewNodeIDFQDN("cp.example"))), first.LocalAddr().(*net.UDPAddr))
	if got := isolationRead(t, first, 20*time.Millisecond); got != nil {
		t.Fatal("source migration bypassed protected global bound")
	}
}

func TestReleaseAllAssociationsAtConnectionReplayBound(t *testing.T) {
	conn := newProtocolConnection(t)
	const peers = 1024
	for i := range peers {
		id := fmt.Sprintf("cp-%d.example", i)
		conn.NodeAssociations[id] = NewNodeAssociation(id, "127.0.0.2")
	}
	for i := 0; i < conn.transactionLimit(); i++ {
		id := fmt.Sprintf("cp-%d.example", i%peers)
		conn.cacheReply(requestKey{peer: "127.0.0.2:8805", sequence: uint32(i), typ: 7}, [32]byte{}, []byte{1}, id, id)
	}
	start := time.Now()
	conn.DeleteAllAssociations()
	elapsed := time.Since(start)
	t.Logf("release %d associations and %d cached outcomes: %v", peers, conn.transactionLimit(), elapsed)
	if conn.GetAssiciationCount() != 0 || len(conn.transport.responses) != 0 || conn.transport.responseExpiry.Len() != 0 || conn.transport.bytes != 0 {
		t.Fatal("release leaked association/replay state")
	}
	if elapsed > time.Second {
		t.Fatalf("release %v exceeds one-second cleanup budget", elapsed)
	}
}

func TestBundleDeletionRetainsAdmissionAndReplayForAdditionalCPAddress(t *testing.T) {
	conn := identityConnection(t)
	setupPeer := identityPeer(t, "127.0.0.2", 0)
	entity := identityPeer(t, "127.0.0.4", 0)
	identitySetup(t, conn, setupPeer, "cp.example")
	assoc := conn.associationByID("cp.example")
	assoc.CPFeatures = []byte{0x10}
	seid := identityEstablish(t, conn, entity, "cp.example", "127.0.0.4")
	first := message.NewSessionDeletionRequest(seid, 20)
	wire, err := message.MarshalDatagram(first, message.NewSessionDeletionRequest(seid, 21))
	if err != nil {
		t.Fatal(err)
	}
	conn.Handle(wire, entity.LocalAddr().(*net.UDPAddr))
	for _, want := range []uint8{ie.CauseRequestAccepted, ie.CauseSessionContextNotFound} {
		response := identityRead(t, entity).(*message.SessionDeletionResponse)
		if cause, _ := response.Cause.Cause(); cause != want {
			t.Fatalf("deletion cause %d, want %d", cause, want)
		}
	}
	conn.Handle(wire, entity.LocalAddr().(*net.UDPAddr))
	for range 2 {
		_ = identityRead(t, entity)
	}
	conn.Handle(protocolWire(t, first), entity.LocalAddr().(*net.UDPAddr))
	if cause, _ := identityRead(t, entity).(*message.SessionDeletionResponse).Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatal("deletion replay lost its association after deleting the last session")
	}
}

func TestReplayFairShareDefersHeavyAssociationWhileRoomRemains(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxReplayEntries = 8
	for i := range 4 {
		conn.cacheReply(requestKey{peer: "127.0.0.2:8805", sequence: uint32(i), typ: 7}, [32]byte{}, []byte{1}, "heavy", "heavy")
	}
	conn.cacheReply(requestKey{peer: "127.0.0.3:8805", sequence: 1, typ: 7}, [32]byte{}, []byte{1}, "light", "light")
	if _, _, err := conn.cachedReply(requestKey{peer: "127.0.0.2:8805", sequence: 99, typ: 7}, [32]byte{}, "heavy"); err == nil {
		t.Fatal("heavy association exceeded its fair share")
	}
	if _, found, err := conn.cachedReply(requestKey{peer: "127.0.0.3:8805", sequence: 99, typ: 7}, [32]byte{}, "light"); found || err != nil {
		t.Fatal("below-share association could not use available capacity")
	}
}

func TestDefaultReplayCapacitySustainsRetentionAtTwoThousandRequestsPerSecond(t *testing.T) {
	conn := newProtocolConnection(t)
	owner := "cp.example"
	conn.NodeAssociations[owner] = NewNodeAssociation(owner, "198.18.0.1")
	const count = 2000 * 60
	for i := range count {
		key := requestKey{peer: "198.18.0.1:8805", sequence: uint32(i), typ: message.MsgTypeSessionModificationRequest}
		if _, found, err := conn.cachedReply(key, [32]byte{}, owner); found || err != nil {
			t.Fatalf("default cache dropped request %d of %d: %v", i, count, err)
		}
		conn.cacheReply(key, [32]byte{}, make([]byte, 80), "198.18.0.1", owner)
	}
	if len(conn.transport.responses) != count {
		t.Fatal("default retention evicted outcomes")
	}
}

func TestReplayBelowByteShareAdmitsWhileGlobalRoomRemains(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.replayMemoryMiB = 16
	for i := range 256 {
		owner := fmt.Sprintf("cp-%d.example", i)
		conn.cacheReply(requestKey{peer: "198.18.0.1:8805", sequence: uint32(i), typ: 7}, [32]byte{}, make([]byte, 80), "198.18.0.1", owner)
	}
	next := requestKey{peer: "198.18.0.1:8805", sequence: 1000, typ: 7}
	if _, found, err := conn.cachedReply(next, [32]byte{}, "cp-0.example"); found || err != nil {
		t.Fatal("below-share association denied available global capacity")
	}
}

func TestCompletingReservedReplyKeepsExpiryOrder(t *testing.T) {
	conn := newProtocolConnection(t)
	a := requestKey{peer: "198.18.0.1:8805", sequence: 1, typ: 52}
	b := requestKey{peer: "198.18.0.2:8805", sequence: 2, typ: 52}
	conn.cacheReply(a, [32]byte{}, nil, "198.18.0.1", "a")
	conn.cacheReply(b, [32]byte{}, []byte{1}, "198.18.0.2", "b")
	conn.transport.responses[b].expires = time.Now().Add(-time.Second)
	conn.cacheReply(a, [32]byte{}, []byte{1}, "198.18.0.1", "a")
	conn.transport.mu.Lock()
	conn.expireResponsesLocked(time.Now())
	conn.transport.mu.Unlock()
	if len(conn.transport.responses) != 1 || conn.transport.responses[a] == nil {
		t.Fatal("late response completion blocked expiration of an older completed outcome")
	}
}
