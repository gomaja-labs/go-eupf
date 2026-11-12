package core

import (
	"bytes"
	"errors"
	"fmt"
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
	key := requestKey{peer: "127.0.0.1:8805", sequence: 1, typ: 5}
	digest := [32]byte{1}
	wire := []byte{1, 2}
	conn.cacheReply(key, digest, wire)
	if got, found, err := conn.cachedReply(key, digest); err != nil || !found || !bytes.Equal(got, wire) {
		t.Fatalf("cached reply=%v,%t,%v", got, found, err)
	}
	if _, _, err := conn.cachedReply(key, [32]byte{2}); err == nil {
		t.Fatal("changed request reused transaction ID")
	}
	if _, _, err := conn.cachedReply(requestKey{peer: "127.0.0.2:8805", sequence: 1, typ: 5}, digest); err == nil {
		t.Fatal("cache exceeded entry bound")
	}
	conn.transport.mu.Lock()
	conn.expireResponsesLocked(time.Now().Add(2 * time.Second))
	conn.transport.mu.Unlock()
	if _, found, err := conn.cachedReply(key, digest); found || err != nil {
		t.Fatal("expired cache entry survived")
	}
}

func TestResponseCacheCapacityRejectsWithoutExecuting(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxTransactions = 1
	peer := transactionPeer(t)
	calls := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeAssociationUpdateRequest: func(_ *PfcpConnection, msg message.Message, _ string) (message.Message, bool, error) {
		calls++
		return message.NewAssociationUpdateResponse(msg.Sequence(), ie.NewNodeIDFQDN("upf.example"), ie.NewCause(ie.CauseRequestAccepted)), false, nil
	}}
	request := message.NewAssociationUpdateRequest(1, ie.NewNodeIDFQDN("synthetic.example"))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	_ = readTransaction(t, peer)
	request.SetSequenceNumber(2)
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	response, err := message.Parse(readTransaction(t, peer))
	if err != nil {
		t.Fatal(err)
	}
	cause, _ := response.(*message.AssociationUpdateResponse).Cause.Cause()
	if cause != ie.CauseNoResourcesAvailable || calls != 1 {
		t.Fatalf("cause=%d executions=%d", cause, calls)
	}
}
func TestLocalRebindCancelsOutstandingTransactions(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	if err := conn.SendMessage(message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp)), peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = readTransaction(t, peer)
	if err := conn.Update("127.0.0.1:0", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if len(conn.transport.pending) != 0 {
		t.Fatal("old local endpoint's transaction survived rebind")
	}
}

func TestExpiredHeartbeatCannotPruneReplacement(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.heartbeatTimeout = time.Second
	peer := transactionPeer(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	request := message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))
	if err := conn.SendMessage(request, peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = readTransaction(t, peer)
	expired := conn.transport.pending[request.Sequence()]
	associationSetup(t, conn, "127.0.0.1", 2)
	conn.requestFailed(expired)
	if conn.GetAssiciationCount() != 1 {
		t.Fatal("old heartbeat timeout deleted a replacement association")
	}
}

func TestHeartbeatAnsweredWhenResponseCacheFull(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxTransactions = 1
	peer := transactionPeer(t)
	conn.cacheReply(requestKey{peer: "192.0.2.1:8805", sequence: 1, typ: message.MsgTypeAssociationSetupRequest}, [32]byte{1}, []byte{1})
	conn.Handle(protocolWire(t, message.NewHeartbeatRequest(4, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))), peer.LocalAddr().(*net.UDPAddr))
	reply, err := message.Parse(readTransaction(t, peer))
	if err != nil {
		t.Fatal(err)
	}
	if reply.MessageType() != message.MsgTypeHeartbeatResponse || len(conn.transport.responses) != 1 {
		t.Fatal("heartbeat either went unanswered or consumed cache capacity")
	}
}

func TestMalformedMatchedReportResponseDoesNotReachApplication(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	called := false
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeSessionReportResponse: func(_ *PfcpConnection, _ message.Message, _ string) (message.Message, bool, error) {
		called = true
		return nil, false, nil
	}}
	request := message.NewSessionReportRequest(1, 0, ie.NewReportType(0, 0, 1, 0))
	if err := conn.SendMessage(request, peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = readTransaction(t, peer)
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(1, request.Sequence())), peer.LocalAddr().(*net.UDPAddr))
	if called || len(conn.transport.pending) != 0 {
		t.Fatal("malformed report response reached application or left retries active")
	}
}

func TestPendingEncodedByteBudget(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	for i := 0; i < 300; i++ {
		request := message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.New(4000, make([]byte, 60000)))
		err := conn.SendMessage(request, peer.LocalAddr().(*net.UDPAddr))
		if err != nil {
			if !errors.Is(err, errTransactionCapacity) {
				t.Fatal(err)
			}
			if conn.transport.pendingBytes > 16<<20 {
				t.Fatal("outbound encoded-byte budget exceeded")
			}
			return
		}
		_ = readTransaction(t, peer)
	}
	t.Fatal("outbound queue never enforced its encoded-byte budget")
}
func TestResponseCacheEncodedByteBudget(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	calls := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeAssociationUpdateRequest: func(_ *PfcpConnection, msg message.Message, _ string) (message.Message, bool, error) {
		calls++
		return message.NewAssociationUpdateResponse(msg.Sequence(), ie.NewNodeIDFQDN("upf.example"), ie.NewCause(ie.CauseRequestAccepted), ie.New(4000, make([]byte, 60000))), false, nil
	}}
	for i := 0; i < 300; i++ {
		conn.Handle(protocolWire(t, message.NewAssociationUpdateRequest(uint32(i+1), ie.NewNodeIDFQDN("synthetic.example"))), peer.LocalAddr().(*net.UDPAddr))
		reply, err := message.Parse(readTransaction(t, peer))
		if err != nil {
			t.Fatal(err)
		}
		cause, _ := reply.(*message.AssociationUpdateResponse).Cause.Cause()
		if cause == ie.CauseNoResourcesAvailable {
			if calls != i || conn.transport.bytes > 16<<20 {
				t.Fatal("cache executed beyond its encoded-byte budget")
			}
			return
		}
	}
	t.Fatal("response cache never enforced its encoded-byte budget")
}

func TestCompletedSequenceCanCarryDifferentRequest(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	calls := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeAssociationUpdateRequest: func(_ *PfcpConnection, msg message.Message, _ string) (message.Message, bool, error) {
		calls++
		return message.NewAssociationUpdateResponse(msg.Sequence(), ie.NewNodeIDFQDN(fmt.Sprintf("result-%d.example", calls)), ie.NewCause(ie.CauseRequestAccepted)), false, nil
	}}
	original := protocolWire(t, message.NewAssociationUpdateRequest(1, ie.NewNodeIDFQDN("first.example")))
	conn.Handle(original, peer.LocalAddr().(*net.UDPAddr))
	first := readTransaction(t, peer)
	changed := protocolWire(t, message.NewAssociationUpdateRequest(1, ie.NewNodeIDFQDN("second.example")))
	conn.Handle(changed, peer.LocalAddr().(*net.UDPAddr))
	second := readTransaction(t, peer)
	if calls != 2 || bytes.Equal(first, second) {
		t.Fatal("completed sequence reuse was mistaken for a retransmission")
	}
	conn.Handle(original, peer.LocalAddr().(*net.UDPAddr))
	replay := readTransaction(t, peer)
	if calls != 2 || !bytes.Equal(first, replay) {
		t.Fatal("original retransmission lost its cached response after sequence reuse")
	}
}
