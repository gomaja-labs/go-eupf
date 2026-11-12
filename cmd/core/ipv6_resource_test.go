package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestUplinkIPv6PrefixesCannotBelongToTwoSessions(t *testing.T) {
	conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{})
	conn.ResourceManager, _ = service.NewResourceManager("", 4)
	for i, address := range []string{"2001:db8::1", "2001:db8::2"} {
		req := message.NewSessionEstablishmentRequest(0, uint32(i+1), ie.NewNodeIDFQDN("test"), ie.NewFSEID(uint64(i+1), net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2)), ie.NewCreatePDR(ie.NewOuterHeaderRemoval(0, 0), ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(5, 0, nil, nil, 0), ie.NewUEIPAddress(1, "", address, 0, 0)), ie.NewFARID(1)))
		reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, peer)
		if err != nil {
			t.Fatal(err)
		}
		cause, _ := reply.(*message.SessionEstablishmentResponse).Cause.Cause()
		want := ie.CauseRequestAccepted
		if i == 1 {
			want = ie.CauseRuleCreationModificationFailure
		}
		if cause != want {
			t.Fatalf("session %d cause=%d want=%d", i, cause, want)
		}
	}
}
