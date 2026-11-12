package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestConnectionRunLargeDatagramAndClose(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	// Runtime timers are enabled with valid production defaults.
	configBefore := config.Conf
	config.Conf.AssociationSetupTimeout = 5
	t.Cleanup(func() { config.Conf = configBefore })
	done := make(chan struct{})
	go func() { conn.Run(); close(done) }()
	req := message.NewHeartbeatRequest(84, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.New(4000, make([]byte, 8000)))
	if _, err := peer.WriteToUDP(protocolWire(t, req), conn.udpConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		conn.Close()
		t.Fatalf("large datagram reply: %v", err)
	}
	reply, err := message.Parse(buf[:n])
	if err != nil || reply.Sequence() != 84 {
		t.Fatalf("reply=%v, %v", reply, err)
	}
	conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not terminate after Close")
	}
}

func TestClosedConnectionRejectsTrafficAndRebind(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.Close()
	peer := transactionPeer(t)
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(7, ie.NewNodeIDFQDN("synthetic.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))), peer.LocalAddr().(*net.UDPAddr))
	if conn.GetAssiciationCount() != 0 {
		t.Error("closed connection processed traffic")
	}
	if err := conn.Update("127.0.0.1:0", "127.0.0.1"); err == nil {
		_ = conn.socket().Close()
		t.Error("closed connection reopened a socket")
	}
}
