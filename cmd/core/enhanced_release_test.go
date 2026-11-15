package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestEnhancedAssociationReleaseFromBothInitiators(t *testing.T) {
	for _, upInitiated := range []bool{false, true} {
		t.Run(map[bool]string{false: "CP", true: "UP"}[upInitiated], func(t *testing.T) {
			conn := sessionLimitConnection(t, 16, nil, nil)
			conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
			node := identityPeer(t, "127.0.0.91", 8805)
			peer := identityPeer(t, "127.0.0.92", 8805)
			conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("enhanced.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewCPFunctionFeatures(4))), node.LocalAddr().(*net.UDPAddr))
			setup := identityRead(t, node).(*message.AssociationSetupResponse)
			if !setup.UPFunctionFeatures.HasEPFAR() {
				t.Fatal("EPFAR was not advertised")
			}
			assoc := conn.associationByID("enhanced.example")
			session := NewSession(11, 77, "", "", false)
			session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
			session.NewUrr(9, 1, ebpf.UrrInfo{})
			assoc.Sessions[11] = session
			if upInitiated {
				conn.SendAssociationReleaseRequest()
				prepare := identityRead(t, node).(*message.AssociationUpdateRequest)
				if !prepare.PFCPAUReqFlags.HasPARPS() || prepare.PFCPAssociationReleaseRequest != nil {
					t.Fatal("UP release did not begin with PARPS")
				}
				conn.Handle(protocolWire(t, message.NewAssociationUpdateResponse(prepare.Sequence(), ie.NewNodeIDFQDN(assoc.ID), ie.NewCause(ie.CauseRequestAccepted))), node.LocalAddr().(*net.UDPAddr))
			} else {
				conn.Handle(protocolWire(t, message.NewAssociationUpdateRequest(2, ie.NewNodeIDFQDN(assoc.ID), ie.NewPFCPAUReqFlags(1))), node.LocalAddr().(*net.UDPAddr))
				if pipelineCause(t, identityRead(t, node)) != ie.CauseRequestAccepted {
					t.Fatal("CP PARPS rejected")
				}
			}
			conn.Handle(protocolWire(t, sessionLimitRequest(assoc.ID, 100, 1)), node.LocalAddr().(*net.UDPAddr))
			if pipelineCause(t, identityRead(t, node)) != ie.CauseNoResourcesAvailable {
				t.Fatal("enhanced preparation admitted another session")
			}
			conn.serviceHeartbeats(time.Now())
			conn.serviceLocalSessionReleases()
			report := identityRead(t, peer).(*message.SessionReportRequest)
			if !report.ReportType.HasUSAR() || !report.PFCPSRReqFlags.HasPSDBU() {
				t.Fatal("enhanced release omitted final session usage")
			}
			conn.serviceHeartbeats(time.Now())
			if pipelineRead(t, node, 10*time.Millisecond) != nil {
				t.Fatal("URSS overtook the last report outcome")
			}
			conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
			conn.serviceHeartbeats(time.Now())
			urss := identityRead(t, node).(*message.AssociationUpdateRequest)
			if !urss.PFCPAssociationReleaseRequest.HasURSS() || urss.PFCPAUReqFlags.HasPARPS() || conn.GetSessionCount() != 0 {
				t.Fatal("URSS did not follow local session deletion")
			}
			conn.Handle(protocolWire(t, message.NewAssociationUpdateResponse(urss.Sequence(), ie.NewNodeIDFQDN(assoc.ID), ie.NewCause(ie.CauseRequestAccepted))), node.LocalAddr().(*net.UDPAddr))
			conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(3, ie.NewNodeIDFQDN(assoc.ID))), node.LocalAddr().(*net.UDPAddr))
			if pipelineCause(t, identityRead(t, node)) != ie.CauseRequestAccepted || conn.GetAssiciationCount() != 0 || len(conn.transport.pending) != 0 {
				t.Fatal("CP Release did not finish enhanced release")
			}
		})
	}
}

func TestEarlyCPReleaseDuringEnhancedDrainAccountsUsage(t *testing.T) {
	for _, reportSent := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-report", true: "after-report"}[reportSent], func(t *testing.T) {
			conn := newProtocolConnection(t)
			node := identityPeer(t, "127.0.0.91", 8805)
			peer := identityPeer(t, "127.0.0.92", 8805)
			conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 10}}
			conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("enhanced.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewCPFunctionFeatures(4))), node.LocalAddr().(*net.UDPAddr))
			_ = identityRead(t, node)
			assoc := conn.associationByID("enhanced.example")
			session := NewSession(11, 77, "", "", false)
			session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
			session.NewUrr(9, 1, ebpf.UrrInfo{})
			assoc.Sessions[11] = session
			conn.Handle(protocolWire(t, message.NewAssociationUpdateRequest(2, ie.NewNodeIDFQDN(assoc.ID), ie.NewPFCPAUReqFlags(1))), node.LocalAddr().(*net.UDPAddr))
			_ = identityRead(t, node)
			before := counterValue(t, PfcpUndeliveredUsage)
			if reportSent {
				conn.serviceHeartbeats(time.Now())
				conn.serviceLocalSessionReleases()
				_ = identityRead(t, peer)
			}
			conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(3, ie.NewNodeIDFQDN(assoc.ID))), node.LocalAddr().(*net.UDPAddr))
			if pipelineCause(t, identityRead(t, node)) != 1 {
				t.Fatal("early Release rejected")
			}
			conn.serviceHeartbeats(time.Now())
			conn.serviceLocalSessionReleases()
			if conn.GetAssiciationCount() != 0 || len(conn.localReleases) != 0 || len(conn.transport.pending) != 0 || counterValue(t, PfcpUndeliveredUsage)-before != 10 {
				t.Fatal("early CP Release lost usage without accounting or retained contexts")
			}
		})
	}
}

func TestEnhancedReleaseRequiresNegotiationAndIgnoresSpareFlags(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.91", 8805)
	identitySetup(t, conn, peer, "enhanced.example")
	assoc := conn.associationByID("enhanced.example")
	for _, flags := range []uint8{0x80, 1} {
		conn.Handle(protocolWire(t, message.NewAssociationUpdateRequest(uint32(flags)+10, ie.NewNodeIDFQDN(assoc.ID), ie.NewPFCPAUReqFlags(flags))), peer.LocalAddr().(*net.UDPAddr))
		response := identityRead(t, peer)
		want := ie.CauseRequestAccepted
		if flags == 1 {
			want = ie.CauseServiceNotSupported
		}
		if pipelineCause(t, response) != want || assoc.enhancedRelease != 0 {
			t.Fatal("unnegotiated or spare flag began enhanced release")
		}
	}
}

func TestEnhancedReleaseHeartbeatCannotShortenPreparation(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.91", 8805)
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("enhanced.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewCPFunctionFeatures(4))), peer.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, peer)
	assoc := conn.associationByID("enhanced.example")
	conn.heartbeatTimeout = time.Millisecond
	conn.heartbeatRetries = 0
	if err := conn.sendAssociationRequest(message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp)), assoc.ID, false, 0); err != nil {
		t.Fatal(err)
	}
	_ = identityRead(t, peer)
	conn.SendAssociationReleaseRequest()
	_ = identityRead(t, peer)
	conn.serviceTransactions(time.Now().Add(2 * time.Millisecond))
	if conn.associationByID(assoc.ID) != assoc || assoc.cleaning || assoc.enhancedRelease != enhancedPreparing {
		t.Fatal("heartbeat timeout shortened enhanced preparation")
	}
}

func TestEnhancedShutdownHasOneBoundAndKeepsUnreclaimedOwnership(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.91", 8805)
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("enhanced.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewCPFunctionFeatures(4))), peer.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, peer)
	assoc := conn.associationByID("enhanced.example")
	assoc.Sessions[11] = NewSession(11, 77, "", "", false)
	conn.BeginShutdown()
	conn.SendAssociationReleaseRequest()
	_ = identityRead(t, peer)
	if assoc.enhancedDeadline.IsZero() {
		t.Fatal("enhanced shutdown has no overall deadline")
	}
	deadline := assoc.enhancedDeadline
	conn.BeginShutdown()
	if assoc.enhancedDeadline != deadline {
		t.Fatal("repeated shutdown extended deadline")
	}
	conn.serviceHeartbeats(deadline.Add(time.Millisecond))
	if conn.FatalError() == nil || assoc.Sessions[11] == nil {
		t.Fatal("incomplete shutdown claimed success or returned unreclaimed ownership")
	}
}
