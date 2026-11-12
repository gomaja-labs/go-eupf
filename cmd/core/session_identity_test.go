package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestLocalSEIDUniqueAcrossAssociations(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	other := "127.0.0.3"
	conn.NodeAssociations[other] = NewNodeAssociation("other", other)
	seen := make(map[uint64]bool)
	for _, addr := range []string{peer, other, peer, other} {
		req := message.NewSessionEstablishmentRequest(0, 1,
			ie.NewNodeIDFQDN(addr), ie.NewFSEID(42, net.ParseIP(addr), nil))
		response, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, addr)
		if err != nil {
			t.Fatal(err)
		}
		fseid, err := response.(*message.SessionEstablishmentResponse).UPFSEID.FSEID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[fseid.SEID] || fseid.SEID == 0 {
			t.Fatalf("UPF reused local SEID %d for peer %s", fseid.SEID, addr)
		}
		seen[fseid.SEID] = true
	}
}

func TestLocalSEIDCannotResolveAnotherPeersSession(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	other := "127.0.0.3"
	conn.NodeAssociations[other] = NewNodeAssociation("other", other)
	for _, addr := range []string{peer, other} {
		_, _, err := HandlePfcpSessionEstablishmentRequest(conn, message.NewSessionEstablishmentRequest(0, 1,
			ie.NewNodeIDFQDN(addr), ie.NewFSEID(42, net.ParseIP(addr), nil)), addr)
		if err != nil {
			t.Fatal(err)
		}
	}
	var seid uint64
	for id := range conn.NodeAssociations[peer].Sessions {
		seid = id
	}
	response, _, err := HandlePfcpSessionDeletionRequest(conn, message.NewSessionDeletionRequest(seid, 2), other)
	if err != nil {
		t.Fatal(err)
	}
	cause, err := response.(*message.SessionDeletionResponse).Cause.Cause()
	if err != nil || cause != ie.CauseSessionContextNotFound {
		t.Fatalf("foreign SEID deletion cause=%d err=%v", cause, err)
	}
	if len(conn.NodeAssociations[other].Sessions) != 1 {
		t.Fatal("foreign SEID deleted the other peer's own session")
	}
}

func TestLocalSEIDWrapSkipsLiveSessions(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	conn.nextSessionID = ^uint64(0)
	conn.NodeAssociations[peer].Sessions[1] = NewSession(1, 10, "", "", false)
	conn.NodeAssociations[peer].Sessions[2] = NewSession(2, 20, "", "", false)
	if got := conn.newLocalSEID(); got != 3 {
		t.Fatalf("wrapped SEID=%d, want first unused nonzero SEID 3", got)
	}
}
