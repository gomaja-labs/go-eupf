package core

// Synthetic regression coverage for response-cache isolation and bundling.

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func isolationSocket(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func isolationRead(t *testing.T, c *net.UDPConn, wait time.Duration) message.Message {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 65535)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	m, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func isolationDrain(c *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, _, err := c.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

func isolationCause(t *testing.T, m message.Message) uint8 {
	t.Helper()
	var c *ie.IE
	switch r := m.(type) {
	case *message.SessionEstablishmentResponse:
		c = r.Cause
	case *message.AssociationSetupResponse:
		c = r.Cause
	case *message.AssociationUpdateResponse:
		c = r.Cause
	default:
		t.Fatalf("unexpected response %T", m)
	}
	v, err := c.Cause()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func isolationSetup(t *testing.T, conn *PfcpConnection, cp *net.UDPConn, seq uint32) {
	t.Helper()
	ip := cp.LocalAddr().(*net.UDPAddr).IP.String()
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(seq, ie.NewNodeIDAddress(netip.MustParseAddr(ip)), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))), cp.LocalAddr().(*net.UDPAddr))
	reply := isolationRead(t, cp, time.Second)
	if reply == nil || isolationCause(t, reply) != ie.CauseRequestAccepted {
		t.Fatalf("association setup failed: %v", reply)
	}
}

func isolationEstablishment(seq uint32, cp string) message.Message {
	return message.NewSessionEstablishmentRequest(0, seq,
		ie.NewNodeIDAddress(netip.MustParseAddr(cp)),
		ie.NewFSEID(uint64(seq), net.ParseIP(cp).To4(), nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, net.IPv4(192, 0, 2, byte(seq)).String(), "", 0, 0)), ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess), ie.NewOuterHeaderCreation(0x0100, seq, "198.51.100.1", "", 0, 0, 0))),
	)
}

func TestResponseCacheUnassociatedFlood(t *testing.T) {
	for _, tc := range []struct {
		name     string
		flooder  string
		fromPeer bool
	}{
		{"unassociated-source", "127.0.0.3", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newProtocolConnection(t) // production defaults: 4096 entries, 60 s retention
			cp := isolationSocket(t, "127.0.0.2")
			isolationSetup(t, conn, cp, 1)
			conn.Handle(protocolWire(t, isolationEstablishment(2, "127.0.0.2")), cp.LocalAddr().(*net.UDPAddr))
			if got := isolationCause(t, isolationRead(t, cp, time.Second)); got != ie.CauseRequestAccepted {
				t.Fatalf("baseline establishment cause %d", got)
			}
			flood := cp
			node := ie.NewNodeIDAddress(netip.MustParseAddr("127.0.0.2"))
			if !tc.fromPeer {
				flood = isolationSocket(t, tc.flooder)
				node = ie.NewNodeIDFQDN("unassociated.example")
			}
			start := time.Now()
			for i := 0; i < conn.transactionLimit(); i++ {
				conn.Handle(protocolWire(t, message.NewAssociationUpdateRequest(uint32(1000+i), node)), flood.LocalAddr().(*net.UDPAddr))
				if i%256 == 0 {
					isolationDrain(flood)
				}
			}
			isolationDrain(flood)
			if conn.transport.responseBudgets["127.0.0.3"] != nil {
				t.Error("unassociated source consumed a replay budget")
			}
			elapsed := time.Since(start)
			conn.Handle(protocolWire(t, isolationEstablishment(3, "127.0.0.2")), cp.LocalAddr().(*net.UDPAddr))
			reply := isolationRead(t, cp, time.Second)
			if got := isolationCause(t, reply); got != ie.CauseRequestAccepted {
				conn.transport.mu.Lock()
				cached := len(conn.transport.responses)
				conn.transport.mu.Unlock()
				t.Errorf("legitimate Session Establishment rejected with cause %d after %d cached outcomes accumulated in %v (retention %v, limit %d)",
					got, cached, elapsed.Round(time.Millisecond), conn.responseRetention, conn.transactionLimit())
			}
		})
	}
}

func TestUnnegotiatedBundleProducesNoResponse(t *testing.T) {
	conn := newProtocolConnection(t)
	src := isolationSocket(t, "127.0.0.4") // no association, no negotiation
	const n = 92                           // 92 x 16 octets fits one 1500-octet IPv4 packet
	var bundle []byte
	for i := 0; i < n; i++ {
		wire := protocolWire(t, message.NewSessionDeletionRequest(uint64(i+1), uint32(i+1)))
		if i < n-1 {
			wire[0] |= 0x04 // FO, clause 7.2.2.1
		}
		bundle = append(bundle, wire...)
	}
	conn.Handle(bundle, src.LocalAddr().(*net.UDPAddr))
	responses, bytesOut := 0, 0
	for {
		m := isolationRead(t, src, 100*time.Millisecond)
		if m == nil {
			break
		}
		responses++
		bytesOut += m.MarshalLen() + 28
	}
	if responses != 0 {
		t.Errorf("one %d-octet IPv4 datagram (%d bundled requests, unassociated source, BUNDL not negotiated) produced %d response datagrams totalling %d octets",
			len(bundle)+28, n, responses, bytesOut)
	}
}

func TestResponseBudgetsProtectConfiguredRetention(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxReplayEntries = 1
	key := requestKey{peer: "127.0.0.1:8805", sequence: 1, typ: 5}
	conn.cacheReply(key, [32]byte{1}, []byte{1})
	created := conn.transport.responseExpiry.Front().Value.(*responseIndex).created
	next := requestKey{peer: "127.0.0.1:9999", sequence: 2, typ: 5}
	if _, _, err := conn.cachedReplyAt(next, [32]byte{2}, created.Add(conn.responseRetention-time.Nanosecond)); err == nil {
		t.Fatal("evicted within minimum replay window")
	}
	if _, _, err := conn.cachedReplyAt(requestKey{peer: "127.0.0.2:8805", sequence: 2, typ: 5}, [32]byte{2}, created); err == nil {
		t.Fatal("another association bypassed the protected global bound")
	}
	if _, _, err := conn.cachedReplyAt(next, [32]byte{2}, created.Add(conn.responseRetention)); err != nil {
		t.Fatal(err)
	}
	if len(conn.transport.responses) != 0 {
		t.Fatal("oldest eligible response was not evicted")
	}
}
func TestResponseIndexesFollowAssociationCleanup(t *testing.T) {
	conn := newProtocolConnection(t)
	for i := 0; i < 100; i++ {
		key := requestKey{peer: "127.0.0.1:8805", sequence: uint32(i), typ: 7}
		conn.cacheReply(key, [32]byte{}, []byte{1})
		conn.forgetPeer("127.0.0.1")
		conn.transport.mu.Lock()
		conn.expireResponsesLocked(time.Now())
		conn.transport.mu.Unlock()
		if conn.transport.responseExpiry.Len() != 0 || len(conn.transport.responseBudgets) != 0 || conn.transport.bytes != 0 {
			t.Fatal("association cleanup leaked cache indexes")
		}
	}
}
func TestBundlingRequiresAssociationFeatures(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		associated, peerSupport, localSupport bool
		count                                 int
		want                                  int
	}{
		{"no_association", false, true, true, 2, 0}, {"no_peer_feature", true, false, true, 2, 0},
		{"no_local_feature", true, true, false, 2, 0}, {"negotiated", true, true, true, 2, 2},
		{"limit", true, true, true, 16, 16}, {"larger_bundle", true, true, true, 17, 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			src := transactionPeer(t)
			if tc.associated {
				associationSetup(t, conn, "127.0.0.1", 1)
				if tc.peerSupport {
					conn.GetAssociation("127.0.0.1").CPFeatures = []byte{0x10}
				}
			}
			if !tc.localSupport {
				conn.GetAssociation("127.0.0.1").UPFeatures = nil
			}
			calls := 0
			conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeSessionDeletionRequest: func(_ *PfcpConnection, m message.Message, _ string) (message.Message, bool, error) {
				calls++
				return message.NewSessionDeletionResponse(m.SEID(), m.Sequence(), ie.NewCause(1)), false, nil
			}}
			msgs := make([]message.Message, tc.count)
			for i := range msgs {
				msgs[i] = message.NewSessionDeletionRequest(1, uint32(i+1))
			}
			wire, err := message.MarshalDatagram(msgs...)
			if err != nil {
				t.Fatal(err)
			}
			conn.Handle(wire, src.LocalAddr().(*net.UDPAddr))
			if calls != tc.want {
				t.Fatalf("executions=%d want=%d", calls, tc.want)
			}
		})
	}
}

func TestResponseIndexCompactionBoundsStaleMetadata(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.cacheReply(requestKey{peer: "127.0.0.1:8805", typ: 5}, [32]byte{}, []byte{1})
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("127.0.1.%d", i+1)
		conn.cacheReply(requestKey{peer: ip + ":8805", typ: 5}, [32]byte{}, []byte{1})
		conn.forgetPeer(ip)
		conn.transport.mu.Lock()
		conn.expireResponsesLocked(time.Now())
		conn.transport.mu.Unlock()
		if conn.transport.responseExpiry.Len() > 2*len(conn.transport.responses)+64 {
			t.Fatal("deleted peers accumulated unbounded expiry metadata behind a live entry")
		}
	}
}

func TestBundledRetransmissionReplaysStandalone(t *testing.T) {
	conn := newProtocolConnection(t)
	src := transactionPeer(t)
	associationSetup(t, conn, "127.0.0.1", 1, ie.NewCPFunctionFeatures(0x10))
	calls := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeSessionDeletionRequest: func(_ *PfcpConnection, m message.Message, _ string) (message.Message, bool, error) {
		calls++
		return message.NewSessionDeletionResponse(m.SEID(), m.Sequence(), ie.NewCause(1)), false, nil
	}}
	first := message.NewSessionDeletionRequest(1, 20)
	wire, err := message.MarshalDatagram(first, message.NewSessionDeletionRequest(1, 21))
	if err != nil {
		t.Fatal(err)
	}
	conn.Handle(wire, src.LocalAddr().(*net.UDPAddr))
	conn.Handle(protocolWire(t, first), src.LocalAddr().(*net.UDPAddr))
	if calls != 2 {
		t.Fatalf("bundled retransmission executed %d handlers, want 2", calls)
	}
}

func TestBundlingUsesStandardFeatureOctets(t *testing.T) {
	conn := newProtocolConnection(t)
	// Feature octets include the four-octet IE header: TS 29.244 V20.1.0
	// tables 8.2.25-1 (7/7) and 8.2.58-1 (5/5).
	if len(conn.featuresOctets) < 3 || conn.featuresOctets[2]&0x40 == 0 {
		t.Error("UP BUNDL is not in IE octet 7")
	}
	associationSetup(t, conn, "127.0.0.1", 1, ie.NewCPFunctionFeatures(0x10))
	peer := transactionPeer(t)
	calls := 0
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeSessionDeletionRequest: func(_ *PfcpConnection, m message.Message, _ string) (message.Message, bool, error) {
		calls++
		return message.NewSessionDeletionResponse(m.SEID(), m.Sequence(), ie.NewCause(1)), false, nil
	}}
	wire, err := message.MarshalDatagram(message.NewSessionDeletionRequest(1, 20), message.NewSessionDeletionRequest(1, 21))
	if err != nil {
		t.Fatal(err)
	}
	conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
	if calls != 2 {
		t.Fatalf("standard CP BUNDL bit did not negotiate bundling: executed %d handlers", calls)
	}
}

func TestBundlingRejectsUnrelatedFeatureBits(t *testing.T) {
	for _, cp := range []bool{false, true} {
		t.Run(fmt.Sprint(cp), func(t *testing.T) {
			conn := newProtocolConnection(t)
			if cp {
				conn.featuresOctets = []byte{0, 0, 0, 0, 0, 0, 0x40}
			}
			associationSetup(t, conn, "127.0.0.1", 1)
			features := []byte{0, 0, 0, 0, 0x10}
			if cp {
				features = []byte{0x10}
			}
			conn.GetAssociation("127.0.0.1").CPFeatures = features
			peer := transactionPeer(t)
			calls := 0
			conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeSessionDeletionRequest: func(_ *PfcpConnection, m message.Message, _ string) (message.Message, bool, error) {
				calls++
				return message.NewSessionDeletionResponse(m.SEID(), m.Sequence(), ie.NewCause(1)), false, nil
			}}
			wire, err := message.MarshalDatagram(message.NewSessionDeletionRequest(1, 20), message.NewSessionDeletionRequest(1, 21))
			if err != nil {
				t.Fatal(err)
			}
			conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
			if calls != 0 {
				t.Fatal("unrelated feature bits enabled bundling")
			}
		})
	}
}
