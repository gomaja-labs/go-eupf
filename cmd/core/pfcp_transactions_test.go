package core

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func transactionPeer(t *testing.T) *net.UDPConn {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return peer
}
func readTransaction(t *testing.T, peer *net.UDPConn) []byte {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65535)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(buf[:n])
}
func TestRetransmittedRequestExecutesOnce(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	calls := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeAssociationSetupRequest: func(_ *PfcpConnection, m message.Message, _ string) (message.Message, bool, error) {
		calls++
		return message.NewAssociationSetupResponse(m.Sequence(), ie.NewCause(ie.CauseRequestAccepted), ie.NewRecoveryTimeStamp(time.Unix(int64(calls), 0))), false, nil
	}}
	req := protocolWire(t, message.NewAssociationSetupRequest(98, ie.NewNodeIDFQDN("synthetic.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))))
	conn.Handle(req, peer.LocalAddr().(*net.UDPAddr))
	first := readTransaction(t, peer)
	conn.Handle(req, peer.LocalAddr().(*net.UDPAddr))
	second := readTransaction(t, peer)
	if calls != 1 || !bytes.Equal(first, second) {
		t.Fatalf("duplicate executed %d times; identical response=%t", calls, bytes.Equal(first, second))
	}
}

func TestRequestRetryBudgetAndResponseMatching(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	other := transactionPeer(t)
	conn.requestTimeout = time.Millisecond
	conn.requestRetries = 2
	req := message.NewAssociationUpdateRequest(0, ie.NewNodeIDFQDN("synthetic.example"))
	if err := conn.SendMessage(req, peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	first := readTransaction(t, peer)
	seq := req.Sequence()
	if conn.matchResponse(message.MsgTypeAssociationUpdateResponse, seq, other.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("wrong endpoint matched")
	}
	if conn.matchResponse(message.MsgTypeHeartbeatResponse, seq, peer.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("wrong procedure matched")
	}
	for i := 1; i <= 2; i++ {
		conn.serviceTransactions(time.Now().Add(time.Duration(i) * time.Second))
		if got := readTransaction(t, peer); !bytes.Equal(got, first) {
			t.Fatal("retransmission changed bytes")
		}
	}
	conn.serviceTransactions(time.Now().Add(3 * time.Second))
	if len(conn.transport.pending) != 0 {
		t.Fatal("retry budget did not terminate transaction")
	}
	_ = peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := peer.ReadFromUDP(make([]byte, 65535)); err == nil {
		t.Fatal("sent beyond retry budget")
	}
	if err := conn.SendMessage(message.NewAssociationUpdateRequest(0, ie.NewNodeIDFQDN("synthetic.example")), peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	reply, err := message.Parse(readTransaction(t, peer))
	if err != nil {
		t.Fatal(err)
	}
	if !conn.matchResponse(message.MsgTypeAssociationUpdateResponse, reply.Sequence(), peer.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("valid response did not match")
	}
	if conn.matchResponse(message.MsgTypeAssociationUpdateResponse, reply.Sequence(), peer.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("duplicate response matched")
	}
}
func TestSequenceWrapSkipsOutstanding(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	send := func() uint32 {
		t.Helper()
		m := message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))
		if err := conn.SendMessage(m, peer.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		_ = readTransaction(t, peer)
		return m.Sequence()
	}
	if send() != 1 {
		t.Fatal("first sequence")
	}
	conn.transport.next = 0xffffff
	if send() != 0 {
		t.Fatal("24-bit wrap")
	}
	if send() != 2 {
		t.Fatal("reused outstanding sequence")
	}
}
func TestResponseCacheBoundsAndExpiry(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxTransactions = 1
	conn.responseRetention = time.Second
	key := requestKey{"127.0.0.1:8805", 1, 5}
	digest := [32]byte{1}
	wire := []byte{1, 2}
	conn.cacheReply(key, digest, wire)
	if got, found, err := conn.cachedReply(key, digest); err != nil || !found || !bytes.Equal(got, wire) {
		t.Fatalf("cached reply=%v,%t,%v", got, found, err)
	}
	if _, _, err := conn.cachedReply(key, [32]byte{2}); err == nil {
		t.Fatal("changed request reused transaction ID")
	}
	if _, _, err := conn.cachedReply(requestKey{"127.0.0.2:8805", 1, 5}, digest); err == nil {
		t.Fatal("cache exceeded entry bound")
	}
	conn.transport.mu.Lock()
	conn.expireResponsesLocked(time.Now().Add(2 * time.Second))
	conn.transport.mu.Unlock()
	if _, found, err := conn.cachedReply(key, digest); found || err != nil {
		t.Fatal("expired cache entry survived")
	}
}
