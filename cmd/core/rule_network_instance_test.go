package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestNetworkInstanceAliasesAndAdmission(t *testing.T) {
	for _, fqdn := range []bool{false, true} {
		for _, inPDI := range []bool{false, true} {
			for _, name := range []string{"internet", "unconfigured"} {
				conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{AllowedApns: "^internet$"})
				instance := ie.NewNetworkInstance(name)
				if fqdn {
					instance = ie.NewNetworkInstanceFQDN(name)
				}
				pdi := []*ie.IE{ie.NewSourceInterface(1), ie.NewUEIPAddress(6, "192.0.2.10", "", 0, 0)}
				forwarding := []*ie.IE{ie.NewDestinationInterface(0), ie.NewOuterHeaderCreation(0x100, 100, "192.0.2.20", "", 0, 0, 0)}
				if inPDI {
					pdi = append(pdi, instance)
				} else {
					forwarding = append(forwarding, instance)
				}
				request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(pdi...), ie.NewFARID(1)), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(forwarding...)))
				reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
				if err != nil {
					t.Fatal(err)
				}
				cause, _ := reply.(*message.SessionEstablishmentResponse).Cause.Cause()
				want := uint8(ie.CauseRequestAccepted)
				if name == "unconfigured" {
					want = ie.CauseRuleCreationModificationFailure
				}
				if cause != want {
					t.Errorf("FQDN=%v PDI=%v name=%s cause=%d want=%d", fqdn, inPDI, name, cause, want)
				}
			}
		}
	}
}
