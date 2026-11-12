package core

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func identityPeer(t *testing.T, address string, port int) *net.UDPConn {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(address), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return peer
}

func identityRead(t *testing.T, peer *net.UDPConn) message.Message {
	t.Helper()
	msg, err := message.Parse(readTransaction(t, peer))
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func identitySetup(t *testing.T, conn *PfcpConnection, peer *net.UDPConn, node string) {
	t.Helper()
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, newIeNodeID(node), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.AssociationSetupResponse)
	if cause, err := response.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("setup cause %d: %v", cause, err)
	}
}

func identityEstablish(t *testing.T, conn *PfcpConnection, peer *net.UDPConn, node, entity string) uint64 {
	t.Helper()
	request := message.NewSessionEstablishmentRequest(0, 2,
		newIeNodeID(node), ie.NewFSEID(77, net.ParseIP(entity).To4(), nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(1, 17, net.ParseIP("127.0.0.1"), nil, 0)), ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.SessionEstablishmentResponse)
	if cause, err := response.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("establishment cause %d: %v", cause, err)
	}
	fseid, err := response.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	return fseid.SEID
}

func TestOriginatedNodeRequestUsesNodeIDAndRegisteredPort(t *testing.T) {
	conn := newProtocolConnection(t)
	source := identityPeer(t, "127.0.0.2", 0)
	node := identityPeer(t, "127.0.0.3", 8805)
	identitySetup(t, conn, source, "127.0.0.3")
	if err := SendHeartbeatRequest(conn, 0, "127.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if got := identityRead(t, node); got.MessageType() != message.MsgTypeHeartbeatRequest {
		t.Fatalf("request %T", got)
	}
	if err := SendAssociationUpdate(conn, conn.GetAssociation("127.0.0.2"), false, true); err != nil {
		t.Fatal(err)
	}
	if got := identityRead(t, node); got.MessageType() != message.MsgTypeAssociationUpdateRequest {
		t.Fatalf("request %T", got)
	}
}

func TestSessionIdentityIndependentOfSourceAddress(t *testing.T) {
	conn := newProtocolConnection(t)
	source := identityPeer(t, "127.0.0.2", 0)
	second := identityPeer(t, "127.0.0.4", 0)
	third := identityPeer(t, "127.0.0.7", 0)
	entity := identityPeer(t, "127.0.0.6", 8805)
	identitySetup(t, conn, source, "cp.example")
	seid := identityEstablish(t, conn, second, "cp.example", "127.0.0.6")
	if !conn.ReleaseSessionByID(seid) {
		t.Fatal("session missing")
	}
	if got := identityRead(t, entity); got.MessageType() != message.MsgTypeSessionReportRequest || got.SEID() != 77 {
		t.Fatalf("report %T SEID %d", got, got.SEID())
	}
	for _, request := range []message.Message{message.NewSessionModificationRequest(seid, 3), message.NewSessionDeletionRequest(seid, 4)} {
		conn.Handle(protocolWire(t, request), third.LocalAddr().(*net.UDPAddr))
		response := identityRead(t, third)
		var cause *ie.IE
		switch response := response.(type) {
		case *message.SessionModificationResponse:
			cause = response.Cause
		case *message.SessionDeletionResponse:
			cause = response.Cause
		}
		if value, err := cause.Cause(); err != nil || value != ie.CauseRequestAccepted || response.SEID() != 77 {
			t.Fatalf("%T cause %d SEID %d: %v", response, value, response.SEID(), err)
		}
	}
}

func TestSharedSourceKeepsSeparateNodeIdentities(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.2", 0)
	identitySetup(t, conn, peer, "first.example")
	identitySetup(t, conn, peer, "second.example")
	if conn.GetAssiciationCount() != 2 {
		t.Fatal("different Node IDs sharing a source did not coexist")
	}
	conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(5, ie.NewNodeIDFQDN("second.example"))), peer.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, peer)
	if conn.GetAssiciationCount() != 1 {
		t.Fatal("release changed another node")
	}
}

func TestEstablishmentCannotBorrowAssociationOfDifferentNode(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.2", 0)
	identitySetup(t, conn, peer, "first.example")
	request := message.NewSessionEstablishmentRequest(0, 2, ie.NewNodeIDAddress(netip.MustParseAddr("127.0.0.2")), ie.NewFSEID(77, net.ParseIP("127.0.0.2"), nil), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0))), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.SessionEstablishmentResponse)
	if cause, _ := response.Cause.Cause(); cause != ie.CauseNoEstablishedPFCPAssociation {
		t.Fatalf("unknown Node ID borrowed association: cause %d", cause)
	}
}

func TestSessionControlAddressesChangeOnlyAfterAcceptedModification(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.2", 0)
	identitySetup(t, conn, peer, "cp.example")
	seid := identityEstablish(t, conn, peer, "cp.example", "127.0.0.6")
	v4, v6 := net.ParseIP("127.0.0.7"), net.ParseIP("2001:db8::7")
	for _, reject := range []bool{true, false} {
		ies := []*ie.IE{ie.NewFSEID(88, v4, v6)}
		if reject {
			ies = append(ies, ie.NewUpdateFAR(ie.NewFARID(999), ie.NewApplyAction(1)))
		}
		req := message.NewSessionModificationRequest(seid, uint32(3+len(ies)), ies...)
		conn.Handle(protocolWire(t, req), peer.LocalAddr().(*net.UDPAddr))
		response := identityRead(t, peer).(*message.SessionModificationResponse)
		cause, _ := response.Cause.Cause()
		session := conn.associationByID("cp.example").Sessions[seid]
		if reject {
			if cause == ie.CauseRequestAccepted || session.RemoteSEID != 77 || !session.CPFSEIDIPv4.Equal(net.ParseIP("127.0.0.6")) || len(session.CPFSEIDIPv6) != 0 {
				t.Fatal("rejected modification changed CP F-SEID")
			}
		} else {
			if cause != ie.CauseRequestAccepted || session.RemoteSEID != 88 || !session.CPFSEIDIPv4.Equal(v4) || !session.CPFSEIDIPv6.Equal(v6) {
				t.Fatal("accepted modification did not retain both CP addresses")
			}
			snapshot := conn.AssociationSnapshots()["cp.example"].Sessions[seid]
			snapshot.CPFSEIDIPv4[0]++
			snapshot.CPFSEIDIPv6[0]++
			if !session.CPFSEIDIPv4.Equal(v4) || !session.CPFSEIDIPv6.Equal(v6) {
				t.Fatal("snapshot aliases CP addresses")
			}
		}
	}
}
