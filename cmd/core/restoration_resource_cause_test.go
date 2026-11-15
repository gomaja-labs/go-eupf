package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestRestorationOccupiedFTEIDUsesRuleFailureOrCapacity(t *testing.T) {
	for _, maximum := range []uint32{1, 4} {
		t.Run(map[uint32]string{1: "capacity", 4: "live-collision"}[maximum], func(t *testing.T) {
			conn := sessionLimitConnection(t, maximum, nil, nil)
			peer := identityPeer(t, "127.0.0.25", 0)
			identitySetup(t, conn, peer, "limit.example")
			first := sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 1)).(*message.SessionEstablishmentResponse)
			created, _ := first.CreatedPDR[0].CreatedPDR()
			tunnel, _ := created.FTEID[0].FTEID()
			request := sessionLimitRequest("limit.example", 3, 1)
			request.PFCPSEReqFlags = ie.NewPFCPSEReqFlags(1)
			request.CreatePDR = []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(7), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(1, tunnel.TEID, conn.n3Address, nil, 0)), ie.NewFARID(1))}
			reply := sessionLimitExchange(t, conn, peer, request).(*message.SessionEstablishmentResponse)
			expected := ie.CauseRuleCreationModificationFailure
			if maximum == 1 {
				expected = ie.CauseNoResourcesAvailable
			}
			if cause := pipelineCause(t, reply); cause != expected {
				t.Fatalf("cause=%d want=%d", cause, expected)
			}
			if maximum != 1 {
				kind, kindErr := reply.FailedRuleID.RuleIDType()
				id, err := reply.FailedRuleID.FailedRuleID()
				if kindErr != nil || err != nil || kind != ie.RuleIDTypePDR || id != 7 {
					t.Fatalf("failed PDR: %d %d %v", kind, id, err)
				}
			} else if reply.FailedRuleID != nil {
				t.Fatal("capacity response carried Failed Rule ID")
			}
		})
	}
}

func TestRestorationUEIPv4OutsideUPFAllocationRangeIsUnavailable(t *testing.T) {
	for _, address := range []string{"192.0.2.0", "198.51.100.1", "192.0.2.1", "192.0.2.3"} {
		t.Run(address, func(t *testing.T) {
			resources, err := service.NewResourceManager("192.0.2.0/30", 4)
			if err != nil {
				t.Fatal(err)
			}
			conn := sessionLimitConnection(t, 4, resources, nil)
			config.Conf.FeatureUEIP = true
			peer := identityPeer(t, "127.0.0.25", 0)
			identitySetup(t, conn, peer, "limit.example")
			request := sessionLimitRequest("limit.example", 2, 1)
			request.PFCPSEReqFlags = ie.NewPFCPSEReqFlags(1)
			request.CreatePDR = []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(7), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, address, "", 0, 0)), ie.NewFARID(1))}
			reply := sessionLimitExchange(t, conn, peer, request)
			expected := ie.CauseRequestAccepted
			if address == "192.0.2.0" || address == "198.51.100.1" {
				expected = ie.CauseSessionRestorationResourceUnavailable
			}
			if cause := pipelineCause(t, reply); cause != expected {
				t.Fatalf("address=%s cause=%d want=%d", address, cause, expected)
			}
		})
	}
}

func TestRestorationExplicitCPAllocatedUEIPNeedsNoUPFPool(t *testing.T) {
	conn := sessionLimitConnection(t, 4, nil, nil)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	request := sessionLimitRequest("limit.example", 2, 1)
	request.PFCPSEReqFlags = ie.NewPFCPSEReqFlags(1)
	request.CreatePDR = []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(7), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, net.IP{198, 51, 100, 1}.String(), "", 0, 0)), ie.NewFARID(1))}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, request)); cause != ie.CauseRequestAccepted {
		t.Fatalf("CP-allocated address rejected: %d", cause)
	}
}
