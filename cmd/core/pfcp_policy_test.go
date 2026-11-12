package core

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/prometheus/client_golang/prometheus"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(c)
	metrics, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	return metrics[0].GetMetric()[0].GetCounter().GetValue()
}

func policyConnection(t *testing.T, options config.UpfConfig) *PfcpConnection {
	t.Helper()
	old := config.Conf
	config.Conf = options
	t.Cleanup(func() { config.Conf = old })
	conn, err := NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", &MapOperationsMock{}, emptyResources(t), nil, nil, DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	return conn
}
func TestPeerAdmissionPrecedesDecoding(t *testing.T) {
	for _, tt := range []struct {
		name   string
		allow  []string
		accept bool
	}{{"empty", nil, true}, {"network", []string{"127.0.0.0/8"}, true}, {"host", []string{"127.0.0.1"}, true}, {"mapped", []string{"::ffff:127.0.0.1/128"}, true}, {"reject", []string{"192.0.2.0/24", "2001:db8::/32"}, false}} {
		t.Run(tt.name, func(t *testing.T) {
			conn := policyConnection(t, config.UpfConfig{PfcpPeerAllowList: tt.allow})
			peer := transactionPeer(t)
			// Unsupported version would elicit a reply if decoding ran before admission.
			conn.Handle([]byte{0x40}, peer.LocalAddr().(*net.UDPAddr))
			_ = peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			_, _, err := peer.ReadFromUDP(make([]byte, 64))
			if (err == nil) != tt.accept {
				t.Fatalf("accept=%t read error=%v", tt.accept, err)
			}
		})
	}
}
func TestAssociationCapacityDoesNotReplaceOtherPeer(t *testing.T) {
	conn := policyConnection(t, config.UpfConfig{PfcpMaxAssociations: 1})
	associationSetup(t, conn, "127.0.0.1", 1)
	request := message.NewAssociationSetupRequest(2, ie.NewNodeIDFQDN("other.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))
	reply, _, _ := HandlePfcpAssociationSetupRequest(conn, request, "127.0.0.2")
	cause, _ := reply.(*message.AssociationSetupResponse).Cause.Cause()
	if cause != ie.CauseNoResourcesAvailable || conn.GetAssiciationCount() != 1 || conn.GetAssociation("127.0.0.1") == nil {
		t.Fatalf("capacity cause=%d count=%d", cause, conn.GetAssiciationCount())
	}
}

func TestMalformedMatchedHeartbeatResponseReleasesProbe(t *testing.T) {
	conn := policyConnection(t, config.UpfConfig{HeartbeatTimeout: 1, HeartbeatRetries: 1, HeartbeatInterval: 1})
	peer := transactionPeer(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	assoc := conn.GetAssociation("127.0.0.1")
	assoc.endpoint = peer.LocalAddr().String()
	conn.serviceHeartbeats(time.Now().Add(2 * time.Second))
	request, err := message.Parse(readTransaction(t, peer))
	if err != nil {
		t.Fatal(err)
	}
	conn.Handle(protocolWire(t, message.NewHeartbeatResponse(request.Sequence())), peer.LocalAddr().(*net.UDPAddr))
	if len(conn.transport.pending) != 0 || assoc.heartbeatInFlight {
		t.Fatal("malformed matched response left a stuck probe or retries")
	}
	if conn.GetAssiciationCount() != 1 {
		t.Fatal("malformed response pruned peer without unreachable budget")
	}
}

func TestTransportPolicyAndHeartbeatGrace(t *testing.T) {
	prunesBefore := counterValue(t, PfcpAssociationPrunes)
	timeoutsBefore := counterValue(t, PfcpRequestTimeouts.WithLabelValues("Heartbeat Request"))
	retriesBefore := counterValue(t, PfcpRequestRetransmissions.WithLabelValues("Heartbeat Request"))
	conn := policyConnection(t, config.UpfConfig{PfcpRequestTimeout: 2, PfcpRequestRetries: 4, PfcpResponseRetention: 30, PfcpMaxTransactions: 128, PfcpMaxAssociations: 16, HeartbeatTimeout: 1, HeartbeatRetries: 1, HeartbeatInterval: 1, HeartbeatFailureGrace: 3})
	if conn.requestTimeout != 2*time.Second || conn.requestRetries != 4 || conn.responseRetention != 30*time.Second || conn.maxTransactions != 128 || conn.maxAssociations != 16 || conn.heartbeatGrace != 3*time.Second {
		t.Fatal("configuration not applied to transport")
	}
	peer := transactionPeer(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	assoc := conn.GetAssociation("127.0.0.1")
	assoc.endpoint = peer.LocalAddr().String()
	now := time.Now()
	conn.serviceHeartbeats(now.Add(2 * time.Second))
	first := readTransaction(t, peer)
	conn.serviceTransactions(now.Add(4 * time.Second))
	if retry := readTransaction(t, peer); !bytes.Equal(retry, first) {
		t.Fatal("heartbeat retry changed bytes")
	}
	if conn.GetAssiciationCount() != 1 {
		t.Fatal("pruned before retry budget")
	}
	conn.serviceTransactions(now.Add(6 * time.Second))
	if conn.GetAssiciationCount() != 1 || assoc.failedAt.IsZero() {
		t.Fatal("grace period not entered")
	}
	failure := assoc.failedAt
	conn.serviceHeartbeats(failure.Add(2 * time.Second))
	if conn.GetAssiciationCount() != 1 {
		t.Fatal("pruned before grace expired")
	}
	// A valid heartbeat received during grace recovers the peer.
	_, _, err := HandlePfcpHeartbeatRequest(conn, message.NewHeartbeatRequest(9, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp)), assoc.Addr)
	if err != nil {
		t.Fatal(err)
	}
	if !assoc.failedAt.IsZero() {
		t.Fatal("valid heartbeat did not clear failure period")
	}
	conn.heartbeatFailed(assoc.Addr)
	failure = assoc.failedAt
	conn.serviceHeartbeats(failure.Add(3 * time.Second))
	if conn.GetAssiciationCount() != 0 {
		t.Fatal("unreachable association survived full grace")
	}
	if counterValue(t, PfcpAssociationPrunes)-prunesBefore != 1 {
		t.Fatal("heartbeat pruning was not counted exactly once")
	}
	if counterValue(t, PfcpRequestTimeouts.WithLabelValues("Heartbeat Request"))-timeoutsBefore != 1 {
		t.Fatal("exhausted heartbeat budget was not counted exactly once")
	}
	if counterValue(t, PfcpRequestRetransmissions.WithLabelValues("Heartbeat Request"))-retriesBefore != 1 {
		t.Fatal("heartbeat retransmission was not counted exactly once")
	}

}

func TestVersionRejectionCompletesHeartbeatProbe(t *testing.T) {
	conn := policyConnection(t, config.UpfConfig{HeartbeatTimeout: 1, HeartbeatInterval: 1})
	peer := transactionPeer(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	assoc := conn.GetAssociation("127.0.0.1")
	assoc.endpoint = peer.LocalAddr().String()
	conn.serviceHeartbeats(time.Now().Add(2 * time.Second))
	request, err := message.Parse(readTransaction(t, peer))
	if err != nil {
		t.Fatal(err)
	}
	conn.Handle(protocolWire(t, message.NewVersionNotSupportedResponse(request.Sequence())), peer.LocalAddr().(*net.UDPAddr))
	if assoc.heartbeatInFlight || len(conn.transport.pending) != 0 {
		t.Fatal("Version Not Supported left a stuck heartbeat probe")
	}
}
func TestMalformedFramingCompletesHeartbeatProbe(t *testing.T) {
	conn := policyConnection(t, config.UpfConfig{HeartbeatTimeout: 1, HeartbeatInterval: 1})
	peer := transactionPeer(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	assoc := conn.GetAssociation("127.0.0.1")
	assoc.endpoint = peer.LocalAddr().String()
	conn.serviceHeartbeats(time.Now().Add(2 * time.Second))
	request, err := message.Parse(readTransaction(t, peer))
	if err != nil {
		t.Fatal(err)
	}
	wire := protocolWire(t, message.NewHeartbeatResponse(request.Sequence(), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp)))
	wire = append(wire, 0, byte(ie.NodeID), 0, 8, 0)
	wire[2], wire[3] = byte((len(wire)-4)>>8), byte(len(wire)-4)
	conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
	if assoc.heartbeatInFlight || len(conn.transport.pending) != 0 {
		t.Fatal("malformed matched response framing left a stuck heartbeat probe")
	}
}
