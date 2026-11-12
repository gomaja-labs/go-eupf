package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog"
)

func releaseProbeConn(t *testing.T) *core.PfcpConnection {
	t.Helper()
	resources, err := service.NewResourceManager("", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, resources, nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	go conn.Run()
	return conn
}

func releaseProbePeer(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func releaseProbeSend(t *testing.T, conn *core.PfcpConnection, peer *net.UDPConn, msg message.Message) {
	t.Helper()
	wire := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(wire); err != nil {
		t.Fatal(err)
	}
	conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
}

func releaseProbeSetupCause(t *testing.T, peer *net.UDPConn) uint8 {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65535)
	for {
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal("no Association Setup Response")
		}
		m, err := message.Parse(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		if r, ok := m.(*message.AssociationSetupResponse); ok {
			cause, _ := r.Cause.Cause()
			return cause
		}
	}
}

func TestShutdownRefusesSetupAcrossAllConnections(t *testing.T) {
	previous := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(previous) })
	old := config.Conf
	config.Conf = config.UpfConfig{PfcpRequestTimeout: 1, PfcpRequestRetries: 0} // graceful period 2 s
	t.Cleanup(func() { config.Conf = old })
	setup := func(node string) message.Message {
		return message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN(node), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))
	}

	t.Run("second connection idle at shutdown", func(t *testing.T) {
		n4, sxb := releaseProbeConn(t), releaseProbeConn(t)
		sgw := releaseProbePeer(t, "127.0.0.91")
		releaseProbeSend(t, sxb, sgw, setup("sgw-c.example"))
		releaseProbeSetupCause(t, sgw) // Sxb association; this CP never answers the release indication
		beginShutdown(n4, sxb)
		safeReleaseConn(n4)
		safeReleaseConn(sxb)
		start := time.Now()
		errc := make(chan error, 1)
		go func() { errc <- waitForAllAssocReleases(context.Background(), n4, sxb) }()
		smf := releaseProbePeer(t, "127.0.0.92")
		releaseProbeSend(t, n4, smf, setup("smf.example")) // an SMF associates with N4 during shutdown
		cause := releaseProbeSetupCause(t, smf)
		err := <-errc
		t.Logf("N4 Setup during shutdown: cause %d; waiter after %v: %v; N4 associations %d", cause, time.Since(start).Round(10*time.Millisecond), err, n4.GetAssiciationCount())
		if cause == ie.CauseRequestAccepted {
			t.Error("a new association was admitted while the process was releasing its associations")
		}
		if err != nil {
			t.Errorf("release waiter failed; run() returns it and the process exits non-zero")
		}
	})

	t.Run("CP re-associates right after its Release", func(t *testing.T) {
		n4 := releaseProbeConn(t)
		smf := releaseProbePeer(t, "127.0.0.93")
		releaseProbeSend(t, n4, smf, setup("smf.example"))
		releaseProbeSetupCause(t, smf)
		safeReleaseConn(n4) // REST POST /pfcp_associations/release or SIGTERM
		start := time.Now()
		releaseProbeSend(t, n4, smf, message.NewAssociationReleaseRequest(2, ie.NewNodeIDFQDN("smf.example")))
		releaseProbeSend(t, n4, smf, message.NewAssociationSetupRequest(3, ie.NewNodeIDFQDN("smf.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000001, 0))))
		cause := releaseProbeSetupCause(t, smf)
		err := waitForAllAssocReleases(context.Background(), n4)
		t.Logf("Setup right after CP Release: cause %d; waiter after %v: %v; associations %d", cause, time.Since(start).Round(10*time.Millisecond), err, n4.GetAssiciationCount())
		if err != nil {
			t.Errorf("release waiter failed; on the REST path run() returns it and the process exits non-zero")
		}
	})
}

func TestShutdownWatcherLatchesWhileManagementReleaseWaits(t *testing.T) {
	old := config.Conf
	config.Conf = config.UpfConfig{PfcpRequestTimeout: 1}
	t.Cleanup(func() { config.Conf = old })
	n4, sxb := releaseProbeConn(t), releaseProbeConn(t)
	peer := releaseProbePeer(t, "127.0.0.38")
	releaseProbeSend(t, sxb, peer, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("cp.example"), ie.NewRecoveryTimeStamp(time.Now())))
	if cause := releaseProbeSetupCause(t, peer); cause != 1 {
		t.Fatal("setup failed")
	}
	safeReleaseConn(n4)
	safeReleaseConn(sxb)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	latched := make(chan struct{})
	go func() { watchShutdown(ctx, done, n4, sxb); close(latched) }()
	cancel()
	select {
	case <-latched:
	case <-time.After(time.Second):
		t.Fatal("signal latch waited for management release")
	}
	newcomer := releaseProbePeer(t, "127.0.0.39")
	releaseProbeSend(t, n4, newcomer, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("new.example"), ie.NewRecoveryTimeStamp(time.Now())))
	if cause := releaseProbeSetupCause(t, newcomer); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("idle connection setup cause %d", cause)
	}
	releaseProbeSend(t, sxb, peer, message.NewAssociationReleaseRequest(2, ie.NewNodeIDFQDN("cp.example")))
	if err := waitForAllAssocReleases(context.Background(), n4, sxb); err != nil {
		t.Fatal(err)
	}
}
