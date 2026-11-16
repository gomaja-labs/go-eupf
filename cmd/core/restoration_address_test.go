package core

import (
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"testing"
)

// The same CP-allocated UE IPv4 address outside the UPF pool is accepted without
// RESTI but rejected with Cause 86 with RESTI.
func TestRestorationAcceptsCPAllocatedUEIPv4(t *testing.T) {
	resources, err := service.NewResourceManager("192.0.2.0/30", 4)
	if err != nil {
		t.Fatal(err)
	}
	conn := sessionLimitConnection(t, 4, resources, nil)
	config.Conf.FeatureUEIP = true
	peer := identityPeer(t, "127.0.0.28", 0)
	identitySetup(t, conn, peer, "limit.example")
	causes := map[bool]uint8{}
	for i, resti := range []bool{false, true} {
		request := sessionLimitRequest("limit.example", uint32(2+i), 1)
		if resti {
			request.PFCPSEReqFlags = ie.NewPFCPSEReqFlags(1)
		}
		address := []string{"198.51.100.1", "198.51.100.2"}[i]
		request.CreatePDR = []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(7), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, address, "", 0, 0)), ie.NewFARID(1))}
		causes[resti] = pipelineCause(t, sessionLimitExchange(t, conn, peer, request))
	}
	t.Logf("CP-allocated UE IPv4 outside pool: without RESTI cause=%d, with RESTI cause=%d", causes[false], causes[true])
	if causes[false] != ie.CauseRequestAccepted || causes[true] != ie.CauseRequestAccepted {
		t.Fatal("restoration rejects an address the UPF accepts for a new session")
	}
}
