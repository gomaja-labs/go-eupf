package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func admittedIdentityReport(t *testing.T) (*PfcpConnection, *NodeAssociation, *net.UDPConn, *message.SessionReportRequest) {
	t.Helper()
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.94", 0)
	assoc := NewNodeAssociation("report.example", "127.0.0.94")
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.94")
	assoc.Sessions[11] = session
	conn.NodeAssociations[assoc.ID] = assoc
	conn.requestTimeout = time.Millisecond
	request := message.NewSessionReportRequest(77, 0, ie.NewReportType(0, 0, 0, 1))
	if err := conn.SendMessage(request, peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = identityRead(t, peer)
	return conn, assoc, peer, request
}

func TestReportCompletionCannotMarkAReplacementSession(t *testing.T) {
	conn, assoc, _, _ := admittedIdentityReport(t)
	delete(assoc.Sessions, 11)
	replacement := NewSession(12, 77, "", "", false)
	replacement.CPFSEIDIPv4 = net.ParseIP("127.0.0.94")
	assoc.Sessions[12] = replacement
	conn.serviceTransactions(time.Now().Add(time.Second))
	if _, marked := assoc.reportFailures[12]; marked {
		t.Fatal("old report completion changed a different local session after CP SEID reuse")
	}
}

func TestAcceptedReportResponseMustUseOriginalLocalSEID(t *testing.T) {
	conn, assoc, peer, request := admittedIdentityReport(t)
	wrong := message.NewSessionReportResponse(12, request.Sequence(), ie.NewCause(ie.CauseRequestAccepted))
	conn.Handle(protocolWire(t, wrong), peer.LocalAddr().(*net.UDPAddr))
	if len(conn.transport.pending) != 0 || assoc.reportFailures[11] != requestInvalid {
		t.Fatal("wrong-SEID response was treated as successful delivery")
	}
}
