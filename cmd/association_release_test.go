package main

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestShutdownReleaseWaitsForCPProcedure(t *testing.T) {
	resources, err := service.NewResourceManager("", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, resources, nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.90")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	setup := message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("shutdown.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))
	wire, err := setup.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
	safeReleaseConn(conn)
	if conn.GetAssiciationCount() != 1 {
		t.Fatal("shutdown removed the association before CP Release or the grace period")
	}
}
