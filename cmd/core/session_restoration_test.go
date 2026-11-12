package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestSessionEstablishmentRecoveryUsesCPAddressAndRejectsStale(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	entity := "192.0.2.77"
	send := func(seq uint32, stamp int64) message.Message {
		req := message.NewSessionEstablishmentRequest(0, seq, ie.NewNodeIDFQDN("test"), ie.NewFSEID(uint64(seq), net.ParseIP(entity), nil), ie.NewRecoveryTimeStamp(time.Unix(stamp, 0)))
		reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, peer)
		if err != nil {
			t.Fatal(err)
		}
		if reply != nil {
			conn.rememberSessionEntity(req, reply, peer)
		}
		return reply
	}
	if send(1, 20) == nil {
		t.Fatal("first timestamp discarded")
	}
	if send(2, 10) != nil {
		t.Fatal("stale establishment received a response instead of being discarded")
	}
	if len(conn.GetAssociation(peer).Sessions) != 1 {
		t.Fatal("stale establishment changed sessions")
	}
	if send(3, 30) == nil {
		t.Fatal("new timestamp discarded")
	}
	if got := len(conn.GetAssociation(peer).Sessions); got != 1 {
		t.Fatalf("restart retained %d sessions", got)
	}
	if got := conn.GetAssociation(peer).recoveries[entity]; !got.Equal(time.Unix(30, 0)) {
		t.Fatal(got)
	}
}
