package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestFTEIDChooseOfferedAddressFamilies(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags uint8
		want  uint8
	}{
		{"IPv4", 5, 1}, {"IPv4AndIPv6", 7, 1}, {"IPv6Unavailable", 6, 76},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{})
			conn.ResourceManager, _ = service.NewResourceManager("", 32)
			req := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil),
				ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(1))),
				ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(test.flags, 0, nil, nil, 0)), ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1)))
			reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, peer)
			if err != nil {
				t.Fatal(err)
			}
			response := reply.(*message.SessionEstablishmentResponse)
			cause, _ := response.Cause.Cause()
			if cause != test.want {
				t.Fatalf("Cause %d, want %d", cause, test.want)
			}
			if cause == 1 {
				if len(response.CreatedPDR) != 1 {
					t.Fatal("missing allocated F-TEID")
				}
				created, err := response.CreatedPDR[0].CreatedPDR()
				if err != nil {
					t.Fatal(err)
				}
				allocated, err := created.FTEID[0].FTEID()
				if err != nil {
					t.Fatal(err)
				}
				if allocated.Flags != 1 || allocated.TEID == 0 || !allocated.IPv4Address.Equal(conn.n3Address) || allocated.IPv6Address != nil {
					t.Fatalf("wrong allocated families: %+v", allocated)
				}
			}
		})
	}
}

func TestCPFunctionTunnelRules(t *testing.T) {
	for _, rule := range []*ie.IE{
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCPFunction), ie.NewFTEID(7, 0, nil, nil, 0)), ie.NewOuterHeaderRemoval(6, 0)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCPFunction), ie.NewOuterHeaderCreation(0x100, 200, "192.0.2.10", "", 0, 0, 0))),
	} {
		if err := validateRuleCapability(rule, nil); err != nil {
			t.Errorf("CP-function tunnel rejected: %v", err)
		}
	}
}
