package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type encodingCountMessage struct {
	message.Message
	calls *int
}

func (m encodingCountMessage) MarshalTo(wire []byte) error {
	*m.calls++
	return m.Message.MarshalTo(wire)
}

func TestStandaloneReplayKeyDoesNotReencodeDecodedRequest(t *testing.T) {
	conn := newProtocolConnection(t)
	cp := transactionPeer(t)
	assoc := NewNodeAssociation("digest.example", cp.LocalAddr().(*net.UDPAddr).IP.String())
	assoc.Sessions[11] = NewSession(11, 77, "", "", false)
	conn.NodeAssociations[assoc.ID] = assoc
	request := message.NewSessionModificationRequest(11, 1)
	wire := protocolWire(t, request)
	calls := 0
	handlers := PfcpHandlerMap{message.MsgTypeSessionModificationRequest: func(_ *PfcpConnection, msg message.Message, _ string) (message.Message, bool, error) {
		return message.NewSessionModificationResponse(77, msg.Sequence(), ie.NewCause(ie.CauseRequestAccepted)), false, nil
	}}
	if err := handlers.handleMessage(conn, encodingCountMessage{request, &calls}, wire, cp.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = identityRead(t, cp)
	if calls != 0 {
		t.Fatalf("replay key encoded the already received standalone request %d times", calls)
	}
}

func TestStandaloneReplayStillIgnoresSpareHeaderBits(t *testing.T) {
	conn := newProtocolConnection(t)
	cp := transactionPeer(t)
	assoc := NewNodeAssociation("digest.example", cp.LocalAddr().(*net.UDPAddr).IP.String())
	assoc.Sessions[11] = NewSession(11, 77, "", "", false)
	conn.NodeAssociations[assoc.ID] = assoc
	executions := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeSessionModificationRequest: func(_ *PfcpConnection, msg message.Message, _ string) (message.Message, bool, error) {
		executions++
		return message.NewSessionModificationResponse(77, msg.Sequence(), ie.NewCause(ie.CauseRequestAccepted)), false, nil
	}}
	wire := protocolWire(t, message.NewSessionModificationRequest(11, 1))
	conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	wire[0] |= 0x18
	conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	if executions != 1 {
		t.Fatal("ignored header flag bits changed replay identity")
	}
	wire[0] &^= 0x18
	wire[15] = 0xff // MP is zero: this entire octet is spare.
	conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	if executions != 1 {
		t.Fatal("ignored header bits changed replay identity")
	}
}

func TestNodeReplayIgnoresSpareOctet(t *testing.T) {
	conn := newProtocolConnection(t)
	cp := transactionPeer(t)
	assoc := NewNodeAssociation("digest.example", cp.LocalAddr().(*net.UDPAddr).IP.String())
	conn.NodeAssociations[assoc.ID] = assoc
	executions := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeAssociationUpdateRequest: func(_ *PfcpConnection, msg message.Message, _ string) (message.Message, bool, error) {
		executions++
		return message.NewAssociationUpdateResponse(msg.Sequence(), ie.NewNodeIDFQDN("up.example"), ie.NewCause(ie.CauseRequestAccepted)), false, nil
	}}
	wire := protocolWire(t, message.NewAssociationUpdateRequest(1, ie.NewNodeIDFQDN(assoc.ID)))
	conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	wire[7] = 0xff
	conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	if executions != 1 {
		t.Fatal("node header's spare octet changed replay identity")
	}
}

func TestReplayPriorityIgnoresOnlySpareBits(t *testing.T) {
	conn := newProtocolConnection(t)
	cp := transactionPeer(t)
	assoc := NewNodeAssociation("digest.example", cp.LocalAddr().(*net.UDPAddr).IP.String())
	assoc.Sessions[11] = NewSession(11, 77, "", "", false)
	conn.NodeAssociations[assoc.ID] = assoc
	executions := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeSessionModificationRequest: func(_ *PfcpConnection, msg message.Message, _ string) (message.Message, bool, error) {
		executions++
		return message.NewSessionModificationResponse(77, msg.Sequence(), ie.NewCause(ie.CauseRequestAccepted)), false, nil
	}}
	wire := protocolWire(t, message.NewSessionModificationRequest(11, 1))
	wire[0] |= 2
	wire[15] = 0x70
	conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	wire[15] = 0x7f
	conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	if executions != 1 {
		t.Fatal("priority's spare bits changed replay identity")
	}
	wire[15] = 0x80
	conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	if executions != 2 {
		t.Fatal("different message priority reused another request's outcome")
	}
}
