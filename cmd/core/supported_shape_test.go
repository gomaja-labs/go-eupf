package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestUnsupportedRuleCombinationsAreRejected(t *testing.T) {
	for _, test := range []struct {
		name  string
		pdi   *ie.IE
		outer bool
	}{
		{"native forwarding without tunnel", ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, "192.0.2.1", "", 0, 0)), false},
		{"native Access interface", ie.NewPDI(ie.NewSourceInterface(0), ie.NewUEIPAddress(6, "192.0.2.1", "", 0, 0)), true},
		{"native source-address lookup", ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(2, "192.0.2.1", "", 0, 0)), true},
		{"N9 creation without removal", ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(1, 10, net.ParseIP("1.2.3.4"), nil, 0)), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, peer := PreparePfcpConnection(t)
			forward := ie.NewForwardingParameters(ie.NewDestinationInterface(0))
			if test.outer {
				forward = ie.NewForwardingParameters(ie.NewDestinationInterface(0), ie.NewOuterHeaderCreation(0x100, 100, "192.0.2.2", "", 0, 0, 0))
			}
			request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), forward), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), test.pdi, ie.NewFARID(1)))
			reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
			if err != nil {
				t.Fatal(err)
			}
			cause, _ := reply.(*message.SessionEstablishmentResponse).Cause.Cause()
			if cause != ie.CauseServiceNotSupported {
				t.Fatalf("unsupported combination accepted, cause=%d", cause)
			}
		})
	}
}

func TestCoreFTEIDRequiresDistinctIngressAddress(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	conn.n9Address = conn.n3Address
	request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), ie.NewFTEID(1, 10, conn.n3Address, nil, 0)), ie.NewFARID(1)))
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
	if err != nil {
		t.Fatal(err)
	}
	cause, _ := reply.(*message.SessionEstablishmentResponse).Cause.Cause()
	if cause != ie.CauseServiceNotSupported {
		t.Fatalf("ambiguous Core F-TEID ingress cause=%d", cause)
	}
}
