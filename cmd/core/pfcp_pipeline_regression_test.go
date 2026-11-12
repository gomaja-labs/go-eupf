package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestReportUsesUniqueLocalSessionIdentity(t *testing.T) {
	pipelineQuiet(t)
	conn := identityConnection(t)
	cp := identityPeer(t, "127.0.0.2", 0)
	entityA := identityPeer(t, "127.0.0.6", 8805)
	entityB := identityPeer(t, "127.0.0.7", 8805)
	pipelineSetup(t, conn, cp, ie.NewNodeIDFQDN("cp.example"), 1)
	seidA := pipelineEstablish(t, conn, cp, "cp.example", 77, "127.0.0.6", 17, 2)
	seidB := pipelineEstablish(t, conn, cp, "cp.example", 77, "127.0.0.7", 18, 3)
	misrouted, delivered := 0, 0
	for i := 0; i < 16; i++ {
		if !conn.ReleaseSessionByID(seidB) {
			t.Fatal("session B missing")
		}
		if m := pipelineRead(t, entityB, 100*time.Millisecond); m != nil {
			delivered++
		}
		if m := pipelineRead(t, entityA, 100*time.Millisecond); m != nil {
			misrouted++
		}
	}
	conn.transport.mu.Lock()
	boundToA := 0
	for _, req := range conn.transport.pending {
		if req.typ == message.MsgTypeSessionReportRequest && req.localSEID == seidA {
			boundToA++
		}
	}
	conn.transport.mu.Unlock()
	t.Logf("16 UP-initiated release reports for session B (UP SEID %d, CP F-SEID 77@127.0.0.7): %d reached 127.0.0.7:8805, %d reached session A's entity 127.0.0.6:8805; %d pending reports bound to session A (UP SEID %d)",
		seidB, delivered, misrouted, boundToA, seidA)
	if misrouted != 0 || boundToA != 0 {
		t.Errorf("reports for session B were sent to session A's CP entity and bound to session A")
	}
}

func TestUPInitiatedSetupPreservesEstablishedSessions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setups []struct{ from, node string }
	}{
		{"two Node IDs share the configured address", []struct{ from, node string }{{"127.0.0.2", "first.example"}, {"127.0.0.2", "second.example"}}},
		{"multi-address CP set up from another of its addresses", []struct{ from, node string }{{"127.0.0.9", "first.example"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pipelineQuiet(t)
			conn := identityConnection(t)
			pfcpPort := identityPeer(t, "127.0.0.2", 8805) // the CP's registered PFCP port
			for i, s := range tc.setups {
				src := identityPeer(t, s.from, 0)
				pipelineSetup(t, conn, src, ie.NewNodeIDFQDN(s.node), uint32(1+i))
				if s.node == "first.example" {
					pipelineEstablish(t, conn, src, "first.example", 77, s.from, 17, 10)
				}
			}
			before := len(conn.associationByID("first.example").Sessions)
			conn.SetRemoteNodes([]AssociationConnector{&DefaultAssociationConnector{address: "127.0.0.2"}})
			conn.RefreshAssociations()
			req, ok := pipelineRead(t, pfcpPort, 300*time.Millisecond).(*message.AssociationSetupRequest)
			if !ok {
				t.Logf("no UP-initiated Setup sent")
				return
			}
			conn.Handle(protocolWire(t, message.NewAssociationSetupResponse(req.Sequence(), ie.NewNodeIDFQDN("first.example"),
				ie.NewCause(ie.CauseRequestAccepted), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))), pfcpPort.LocalAddr().(*net.UDPAddr))
			after := len(conn.associationByID("first.example").Sessions)
			conn.RefreshAssociations() // next association_setup_timeout tick
			_, repeated := pipelineRead(t, pfcpPort, 300*time.Millisecond).(*message.AssociationSetupRequest)
			t.Logf("associations=%d; UP-initiated Setup sent to 127.0.0.2:8805 although first.example is associated; sessions of first.example before=%d after=%d; Setup repeated on the next tick=%v",
				conn.GetAssiciationCount(), before, after, repeated)
			if after != before {
				t.Errorf("UP-initiated Setup Response deleted %d established sessions of an existing association", before-after)
			}
		})
	}
}

func TestHeartbeatCostIndependentOfSessionCount(t *testing.T) {
	pipelineQuiet(t)
	for _, n := range []int{0, 10000, 65535} {
		conn := identityConnection(t)
		cp := identityPeer(t, "127.0.0.2", 0)
		pipelineSetup(t, conn, cp, ie.NewNodeIDFQDN("cp.example"), 1)
		assoc := conn.associationByID("cp.example")
		for i := 0; i < n; i++ {
			s := NewSession(uint64(1000+i), uint64(1000+i), "", "", false)
			s.CPFSEIDIPv4 = net.IPv4(127, 1, byte(i>>8), byte(i)).To4()
			assoc.Sessions[s.LocalSEID] = s
		}
		attacker := identityPeer(t, "127.0.0.99", 0) // admitted (empty allow-list), unassociated
		const rounds = 20
		start := time.Now()
		for i := 0; i < rounds; i++ {
			conn.Handle(protocolWire(t, message.NewHeartbeatRequest(uint32(10+i), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))), attacker.LocalAddr().(*net.UDPAddr))
		}
		per := time.Since(start) / rounds
		answered := pipelineDrain(attacker)
		t.Logf("sessions=%d: %v per unassociated Heartbeat Request (%d answered); saturation at about %.0f requests/s",
			n, per, answered, float64(time.Second)/float64(per))
		conn.Close()
	}
}

func TestHeartbeatPolicyChangeCompletesPendingProbe(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.28", 0)
	conn.heartbeatTimeout = time.Second
	req := message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(time.Now()))
	if err := conn.SendMessage(req, peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	pending := conn.transport.pending[req.Sequence()]
	calls := 0
	pending.onComplete = func(result requestResult) {
		calls++
		if result.outcome != requestCanceled {
			t.Errorf("probe completed as %s", result.outcome)
		}
	}
	conn.SetHeartbeatTimeout(2)
	if calls != 1 {
		t.Fatalf("terminal cancellation calls %d, want 1", calls)
	}
	conn.serviceTransactions(time.Now().Add(time.Minute))
	if calls != 1 {
		t.Fatal("probe completed twice")
	}
}

func TestEverySessionOriginatorUsesLocalIdentity(t *testing.T) {
	for _, originator := range []string{"release_id", "release_user", "release", "usage", "adc", "dldr", "queued"} {
		t.Run(originator, func(t *testing.T) {
			pipelineQuiet(t)
			conn := identityConnection(t)
			cp := identityPeer(t, "127.0.0.2", 0)
			first := identityPeer(t, "127.0.0.6", 8805)
			second := identityPeer(t, "127.0.0.7", 8805)
			pipelineSetup(t, conn, cp, ie.NewNodeIDFQDN("cp.example"), 1)
			pipelineEstablish(t, conn, cp, "cp.example", 77, "127.0.0.6", 17, 2)
			seid := pipelineEstablish(t, conn, cp, "cp.example", 77, "127.0.0.7", 18, 3)
			assoc := conn.associationByID("cp.example")
			assoc.Sessions[seid].IMSI = "001010000000017"
			switch originator {
			case "release_id":
				if !conn.ReleaseSessionByID(seid) {
					t.Fatal("session missing")
				}
			case "release_user":
				if !conn.ReleaseSessionByUserID("001010000000017", "") {
					t.Fatal("subscriber missing")
				}
			case "release":
				SendSessionReportSessionRelease(conn, seid, 0, assoc.ID, false, []uint16{1})
			case "usage":
				SendSessionReportUsage(conn, seid, 0, assoc.ID, 9, 0, 40, 20, false)
			case "adc":
				SendSessionReportADC(conn, seid, 0, assoc.ID, 9, 0, "permit out ip from any to any", false)
			case "dldr":
				SendDownlinkNotificationReport(conn, seid, 0, assoc.ID, 1, false)
			case "queued":
				conn.sendQueued([]queuedMessage{{msg: message.NewSessionReportRequest(77, 0, ie.NewReportType(0, 0, 0, 1)), association: assoc.ID, localSEID: seid}})
			}
			report := identityRead(t, second)
			if report.MessageType() != message.MsgTypeSessionReportRequest || report.SEID() != 77 {
				t.Fatalf("wrong report %T", report)
			}
			if wrong := pipelineRead(t, first, 10*time.Millisecond); wrong != nil {
				t.Fatal("report sent to another CP entity")
			}
			req := conn.transport.pending[report.Sequence()]
			if req == nil || req.localSEID != seid {
				t.Fatal("completion bound to another session")
			}
		})
	}
}

func TestAddressReferencesFollowSessionChanges(t *testing.T) {
	conn := identityConnection(t)
	cp := identityPeer(t, "127.0.0.2", 0)
	identitySetup(t, conn, cp, "cp.example")
	first := identityEstablish(t, conn, cp, "cp.example", "127.0.0.6")
	// A distinct sequence is required for a second establishment.
	second := pipelineEstablish(t, conn, cp, "cp.example", 78, "127.0.0.6", 2, 3)
	assoc := conn.associationByID("cp.example")
	if conn.GetAssociation("127.0.0.6") != assoc {
		t.Fatal("missing CP F-SEID address")
	}
	conn.Handle(protocolWire(t, message.NewSessionModificationRequest(first, 4, ie.NewFSEID(99, net.ParseIP("127.0.0.7"), nil))), cp.LocalAddr().(*net.UDPAddr))
	if cause := pipelineCause(t, identityRead(t, cp)); cause != ie.CauseRequestAccepted {
		t.Fatalf("modification cause %d", cause)
	}
	if conn.GetAssociation("127.0.0.6") != assoc || conn.GetAssociation("127.0.0.7") != assoc {
		t.Fatal("modification lost address references")
	}
	conn.Handle(protocolWire(t, message.NewSessionDeletionRequest(second, 5)), cp.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, cp)
	if conn.GetAssociation("127.0.0.6") != nil {
		t.Fatal("final address reference survived deletion")
	}
	if conn.GetAssociation("127.0.0.7") != assoc {
		t.Fatal("deletion removed another session's address")
	}
}
