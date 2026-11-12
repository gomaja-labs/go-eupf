package core

import (
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestHeartbeatUnknownPeer(t *testing.T) {
	conn := newProtocolConnection(t)
	reply := exchangeProtocolDatagram(t, conn, protocolWire(t, message.NewHeartbeatRequest(47, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))))
	if reply == nil || reply.MessageType() != message.MsgTypeHeartbeatResponse || reply.Sequence() != 47 {
		t.Fatalf("unknown-peer heartbeat reply = %v", reply)
	}
}

func TestHeartbeatUnexpectedResponseDoesNotBlock(t *testing.T) {
	conn := newProtocolConnection(t)
	assoc := NewNodeAssociation("synthetic.example", "127.0.0.1")
	conn.NodeAssociations[assoc.Addr] = assoc
	done := make(chan struct{})
	go func() {
		_, _, _ = HandlePfcpHeartbeatResponse(conn, message.NewHeartbeatResponse(48, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))), assoc.Addr)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		// Unblock the pre-fix implementation so the regression leaves no goroutine.
		select {
		case <-assoc.HeartbeatChannel:
		case <-time.After(time.Second):
		}
		t.Fatal("unexpected heartbeat response blocked the receive handler")
	}
}

func TestHeartbeatMissingTimestamp(t *testing.T) {
	conn := newProtocolConnection(t)
	if reply := exchangeProtocolDatagram(t, conn, protocolWire(t, message.NewHeartbeatRequest(49))); reply != nil {
		t.Fatalf("missing timestamp response = %v", reply)
	}
	_, _, err := HandlePfcpHeartbeatResponse(conn, message.NewHeartbeatResponse(49), "127.0.0.1")
	if err == nil {
		t.Fatal("missing response timestamp was accepted")
	}
}
