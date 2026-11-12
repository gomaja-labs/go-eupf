package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestCreatedPDRReturnsBothChosenResources(t *testing.T) {
	old := config.Conf
	config.Conf.FeatureUEIP = true
	t.Cleanup(func() { config.Conf = old })
	conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{FeatureUEIP: true})
	conn.ResourceManager, _ = service.NewResourceManager("192.0.2.0/30", 4)
	req := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(1, net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2)), ie.NewCreatePDR(ie.NewOuterHeaderRemoval(0, 0), ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(5, 0, nil, nil, 0), ie.NewUEIPAddress(16, "", "", 0, 0)), ie.NewFARID(1)))
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, peer)
	if err != nil {
		t.Fatal(err)
	}
	response := reply.(*message.SessionEstablishmentResponse)
	cause, _ := response.Cause.Cause()
	if cause != 1 {
		t.Fatal(cause)
	}
	if len(response.CreatedPDR) != 1 {
		t.Fatal("missing Created PDR")
	}
	fields, err := response.CreatedPDR[0].CreatedPDR()
	if err != nil {
		t.Fatal(err)
	}
	if len(fields.FTEID) != 1 || len(fields.UEIPAddress) != 1 {
		t.Fatal("Created PDR omitted a simultaneously allocated resource")
	}
}
