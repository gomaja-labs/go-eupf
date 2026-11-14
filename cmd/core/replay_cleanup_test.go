package core

import (
	"errors"
	"testing"

	"github.com/gomaja-labs/go-pfcp/message"
)

func TestAssociationCleanupReturnsOnlyRemovedReplayReservations(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxReplayEntries = 4
	for index := range 4 {
		owner := "first.example"
		if index >= 2 {
			owner = "second.example"
		}
		typ := message.MsgTypeSessionModificationRequest
		if index == 0 {
			typ = message.MsgTypeAssociationSetupRequest
		}
		conn.cacheReply(requestKey{peer: "127.0.0.2:8805", sequence: uint32(index + 1), typ: typ}, [32]byte{}, []byte{1}, owner, owner)
	}
	conn.forgetPeerTransactions("first.example", true, "", nil)
	if len(conn.transport.responses) != 3 || conn.transport.responseExpiry.Len() != 3 {
		t.Fatal("selective cleanup removed the retained setup or another owner")
	}
	key := requestKey{peer: "127.0.0.2:8805", sequence: 5, typ: message.MsgTypeSessionModificationRequest}
	if _, found, err := conn.cachedReply(key, [32]byte{}, "first.example"); err != nil || found {
		t.Fatalf("removed reservation was not returned: found=%t error=%v", found, err)
	}
	if _, _, err := conn.cachedReply(requestKey{peer: "127.0.0.3:8805", sequence: 6, typ: message.MsgTypeSessionModificationRequest}, [32]byte{}, "third.example"); !errors.Is(err, errTransactionCapacity) {
		t.Fatalf("cleanup returned another outcome's reservation: %v", err)
	}
	conn.forgetPeer("first.example")
	conn.forgetPeer("second.example")
	if len(conn.transport.responses) != 0 || conn.transport.bytes != 0 || conn.transport.responseExpiry.Len() != 0 {
		t.Fatal("cleanup retained replay indexes")
	}
	if _, found, err := conn.cachedReply(key, [32]byte{}, "first.example"); err != nil || found {
		t.Fatalf("full cleanup retained a reservation: %t %v", found, err)
	}
}
