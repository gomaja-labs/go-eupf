package core

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestLocalSessionReleaseDeletesAndSendsUISR(t *testing.T) {
	conn, assoc, _, peer := downlinkFixture(t, true)
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.92")
	assoc.Sessions[11] = session
	if err := conn.ResourceManager.AdmitSession(11); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ReleaseSessionByID(11); err != nil {
		t.Fatal("session release refused")
	}
	report := identityRead(t, peer).(*message.SessionReportRequest)
	if !report.ReportType.HasUISR() || report.PFCPSRReqFlags.HasPSDBU() || report.SEID() != 77 || conn.GetSessionCount() != 0 {
		t.Fatal("release did not delete locally and send UISR without unnegotiated PSDBU to the CP F-SEID")
	}
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
	if _, err := conn.ReleaseSessionByID(11); err == nil {
		t.Fatal("deleted session released twice")
	}
}

func TestLocalSessionReleaseUsageAndTerminalOutcomes(t *testing.T) {
	for _, outcome := range []string{"accepted", "rejected", "invalid", "timeout"} {
		t.Run(outcome, func(t *testing.T) {
			conn, assoc, _, peer := downlinkFixture(t, true)
			conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 12, DownlinkVolume: 8}}
			conn.requestTimeout = time.Millisecond
			conn.requestRetries = 1
			session := NewSession(11, 77, "", "", false)
			session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
			session.NewUrr(9, 1, ebpf.UrrInfo{})
			assoc.Sessions[11] = session
			if err := conn.ResourceManager.SetSessionCapacity(1); err != nil {
				t.Fatal(err)
			}
			if err := conn.ResourceManager.AdmitSession(11); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ReleaseSessionByID(11); err != nil {
				t.Fatal(err)
			}
			report := identityRead(t, peer).(*message.SessionReportRequest)
			if !report.ReportType.HasUSAR() || report.PFCPSRReqFlags.HasPSDBU() || len(report.UsageReport) != 1 {
				t.Fatal("missing final usage or unexpected unnegotiated deletion indication")
			}
			fields, err := report.UsageReport[0].UsageReportWithinSessionReportRequest()
			if err != nil {
				t.Fatal(err)
			}
			volume, err := fields.VolumeMeasurement.VolumeMeasurement()
			if err != nil || volume.UplinkVolume != 12 || volume.DownlinkVolume != 8 || !fields.UsageReportTrigger.HasTEBUR() {
				t.Fatalf("final usage=%+v error=%v", volume, err)
			}
			if len(conn.localReleases) != 1 || conn.GetSessionCount() != 0 {
				t.Fatal("live session and retained report context confused")
			}
			if err := conn.ResourceManager.AdmitSession(12); err != nil {
				t.Fatal("successful deletion did not reclaim admission", err)
			}
			conn.serviceTransactions(time.Now().Add(2 * time.Millisecond))
			retry := identityRead(t, peer)
			if !bytes.Equal(protocolWire(t, report), protocolWire(t, retry)) {
				t.Fatal("final report retry changed bytes")
			}
			beforeLost := counterValue(t, PfcpUndeliveredUsage)
			if outcome == "timeout" {
				conn.serviceTransactions(time.Now().Add(time.Second))
			} else {
				cause := ie.NewCause(ie.CauseRequestAccepted)
				if outcome == "rejected" {
					cause = ie.NewCause(ie.CauseSystemFailure)
				}
				if outcome == "invalid" {
					cause = nil
				}
				response := message.NewSessionReportResponse(11, report.Sequence(), cause)
				for range 2 {
					conn.Handle(protocolWire(t, response), peer.LocalAddr().(*net.UDPAddr))
				}
			}
			if len(conn.localReleases) != 0 || conn.localReleaseBytes != 0 || len(conn.transport.pending) != 0 {
				t.Fatal("terminal report retained context or replayed completion")
			}
			lost := counterValue(t, PfcpUndeliveredUsage) - beforeLost
			wantLost := float64(20)
			if outcome == "accepted" {
				wantLost = 0
			}
			if lost != wantLost {
				t.Fatalf("undelivered octets=%g want=%g", lost, wantLost)
			}
			if _, err := conn.ReleaseSessionByID(11); err == nil {
				t.Fatal("released same session twice")
			}
			if err := conn.ResourceManager.AdmitSession(13); err == nil {
				t.Fatal("duplicate release returned another session's admission")
			}
		})
	}
}

func TestLocalReleaseWaitsForFinalUsageGraceAndReclaimsOnce(t *testing.T) {
	conn, assoc, _, peer := downlinkFixture(t, true)
	plane := &delayedUsagePlane{}
	conn.mapOperations = plane
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
	session.NewUrr(9, 1, ebpf.UrrInfo{})
	assoc.Sessions[11] = session
	if err := conn.ResourceManager.SetSessionCapacity(1); err != nil {
		t.Fatal(err)
	}
	if err := conn.ResourceManager.AdmitSession(11); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ReleaseSessionByID(11); err != nil {
		t.Fatal(err)
	}
	if plane.transaction == nil {
		t.Fatal("local release did not start the deletion journal")
	}
	if conn.GetSessionCount() != 0 || len(conn.transport.pending) != 0 {
		t.Fatal("final report sent before usage grace")
	}
	if err := conn.ResourceManager.AdmitSession(12); err == nil {
		t.Fatal("admission returned before reclamation")
	}
	plane.transaction.finish(t)
	conn.serviceLocalSessionReleases()
	report := identityRead(t, peer).(*message.SessionReportRequest)
	fields, err := report.UsageReport[0].UsageReportWithinSessionReportRequest()
	if err != nil {
		t.Fatal(err)
	}
	volume, err := fields.VolumeMeasurement.VolumeMeasurement()
	if err != nil || volume.UplinkVolume != 40 || volume.DownlinkVolume != 20 {
		t.Fatal("final counter snapshot missing", err)
	}
	if err := conn.ResourceManager.AdmitSession(12); err != nil {
		t.Fatal("admission retained after reclamation", err)
	}
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
}

func TestLocalReleaseDoesNotReissueUnacknowledgedEarlierUsage(t *testing.T) {
	conn, assoc, _, peer := downlinkFixture(t, true)
	maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 10}}
	conn.mapOperations = maps
	conn.requestTimeout = time.Millisecond
	conn.requestRetries = 0
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
	session.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 1})
	assoc.Sessions[11] = session
	conn.SendReports()
	_ = identityRead(t, peer)
	maps.urr.UplinkVolume = 15
	before := counterValue(t, PfcpUndeliveredUsage)
	if _, err := conn.ReleaseSessionByID(11); err != nil {
		t.Fatal(err)
	}
	conn.serviceTransactions(time.Now().Add(time.Second))
	conn.serviceLocalSessionReleases()
	report := identityRead(t, peer).(*message.SessionReportRequest)
	fields, err := report.UsageReport[0].UsageReportWithinSessionReportRequest()
	if err != nil {
		t.Fatal(err)
	}
	volume, err := fields.VolumeMeasurement.VolumeMeasurement()
	if err != nil || volume.UplinkVolume != 5 || counterValue(t, PfcpUndeliveredUsage)-before != 10 {
		t.Fatal("unacknowledged window was reissued or lost without accounting")
	}
}

func TestLocalReleaseDoesNotMergeAnotherURRLifetime(t *testing.T) {
	conn, assoc, _, peer := downlinkFixture(t, true)
	maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 10}}
	conn.mapOperations = maps
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
	session.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 1})
	assoc.Sessions[11] = session
	conn.SendReports()
	old := identityRead(t, peer)
	session.NewUrr(9, 2, ebpf.UrrInfo{})
	maps.urr.UplinkVolume = 5
	before := counterValue(t, PfcpUndeliveredUsage)
	if _, err := conn.ReleaseSessionByID(11); err != nil {
		t.Fatal(err)
	}
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, old.Sequence(), ie.NewCause(ie.CauseSystemFailure))), peer.LocalAddr().(*net.UDPAddr))
	conn.serviceLocalSessionReleases()
	report := identityRead(t, peer).(*message.SessionReportRequest)
	fields, err := report.UsageReport[0].UsageReportWithinSessionReportRequest()
	if err != nil {
		t.Fatal(err)
	}
	volume, err := fields.VolumeMeasurement.VolumeMeasurement()
	if err != nil || volume.UplinkVolume != 5 || counterValue(t, PfcpUndeliveredUsage)-before != 10 {
		t.Fatal("another URR generation's usage was merged or lost silently")
	}
}

func TestLocalReleaseDeletionFailureKeepsOwnership(t *testing.T) {
	conn, assoc, _, peer := downlinkFixture(t, true)
	conn.mapOperations = &releaseCleanupMaps{failures: 100}
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
	session.NewFar(1, 1, ebpf.FarInfo{Action: 2})
	assoc.Sessions[11] = session
	if err := conn.ResourceManager.SetSessionCapacity(1); err != nil {
		t.Fatal(err)
	}
	if err := conn.ResourceManager.AdmitSession(11); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ReleaseSessionByID(11); err == nil {
		t.Fatal("failed deletion was accepted")
	}
	if conn.GetSessionCount() != 1 || len(conn.localReleases) != 0 || len(conn.transport.pending) != 0 {
		t.Fatal("failed deletion removed context or reported PSDBU")
	}
	if err := conn.ResourceManager.AdmitSession(12); err == nil {
		t.Fatal("failed deletion returned admission")
	}
	// Allow the fixture's final cleanup to recover normally.
	conn.mapOperations = &MapOperationsMock{}
}

func TestRequestsCrossingLocalReleaseFindNoLiveSession(t *testing.T) {
	conn, assoc, _, peer := downlinkFixture(t, true)
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
	assoc.Sessions[11] = session
	if _, err := conn.ReleaseSessionByID(11); err != nil {
		t.Fatal(err)
	}
	_ = identityRead(t, peer)
	node := identityPeer(t, "127.0.0.93", 0)
	for _, request := range []message.Message{message.NewSessionModificationRequest(11, 81), message.NewSessionDeletionRequest(11, 82)} {
		conn.Handle(protocolWire(t, request), node.LocalAddr().(*net.UDPAddr))
		response := identityRead(t, node)
		if pipelineCause(t, response) != ie.CauseSessionContextNotFound || response.SEID() != 0 {
			t.Fatalf("crossing request received %T with SEID %d", response, response.SEID())
		}
	}
}

func TestLocalReleaseWaitsForEarlierUsageOutcome(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "accepted"}[accepted], func(t *testing.T) {
			conn, assoc, _, peer := downlinkFixture(t, true)
			maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 10}}
			conn.mapOperations = maps
			session := NewSession(11, 77, "", "", false)
			session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
			session.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 1})
			assoc.Sessions[11] = session
			conn.SendReports()
			earlier := identityRead(t, peer).(*message.SessionReportRequest)
			maps.urr.UplinkVolume = 15
			if _, err := conn.ReleaseSessionByID(11); err != nil {
				t.Fatal(err)
			}
			if conn.localReleases[11].waiting != 1 || len(conn.transport.pending) != 1 {
				t.Fatal("PSDBU overtook an earlier usage report")
			}
			cause := ie.CauseSystemFailure
			if accepted {
				cause = ie.CauseRequestAccepted
			}
			conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, earlier.Sequence(), ie.NewCause(cause))), peer.LocalAddr().(*net.UDPAddr))
			conn.serviceLocalSessionReleases()
			final := identityRead(t, peer).(*message.SessionReportRequest)
			fields, err := final.UsageReport[0].UsageReportWithinSessionReportRequest()
			if err != nil {
				t.Fatal(err)
			}
			volume, err := fields.VolumeMeasurement.VolumeMeasurement()
			want := uint64(15)
			if accepted {
				want = 5
			}
			if err != nil || volume.UplinkVolume != want {
				t.Fatalf("final=%+v want=%d error=%v", volume, want, err)
			}
		})
	}
}

func TestLocalReleaseCPContextCrossingsDuringFinalGrace(t *testing.T) {
	for _, crossing := range []string{"entity-restart", "setup-replacement", "association-release"} {
		t.Run(crossing, func(t *testing.T) {
			conn, assoc, _, peer := downlinkFixture(t, true)
			plane := &delayedUsagePlane{}
			conn.mapOperations = plane
			session := NewSession(11, 77, "", "", false)
			session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
			session.NewUrr(9, 1, ebpf.UrrInfo{})
			assoc.Sessions[11] = session
			if crossing != "entity-restart" {
				assoc.sessionEntities[11] = session.CPFSEIDIPv4.String()
			}
			conn.indexSession(assoc, session, 1)
			stamp := time.Unix(1700000000, 0)
			assoc.recoveries[session.CPFSEIDIPv4.String()] = stamp
			before := counterValue(t, PfcpUndeliveredUsage)
			if _, err := conn.ReleaseSessionByID(11); err != nil {
				t.Fatal(err)
			}
			switch crossing {
			case "entity-restart":
				// The former F-SEID address must still resolve to the delivery context.
				conn.Handle(protocolWire(t, message.NewHeartbeatRequest(5, ie.NewRecoveryTimeStamp(stamp.Add(time.Second)))), peer.LocalAddr().(*net.UDPAddr))
				_ = identityRead(t, peer)
			case "setup-replacement":
				conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(5, ie.NewNodeIDFQDN(assoc.ID), ie.NewRecoveryTimeStamp(stamp))), peer.LocalAddr().(*net.UDPAddr))
				_ = identityRead(t, peer)
			case "association-release":
				conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(5, ie.NewNodeIDFQDN(assoc.ID))), peer.LocalAddr().(*net.UDPAddr))
				_ = identityRead(t, peer)
			}
			plane.transaction.finish(t)
			conn.serviceLocalSessionReleases()
			if pipelineRead(t, peer, 10*time.Millisecond) != nil || len(conn.localReleases) != 0 || counterValue(t, PfcpUndeliveredUsage)-before != 60 {
				t.Fatal("old CP context received final report or unsent usage was not accounted")
			}
		})
	}
}

func TestLocalReleaseCPContextCrossingsAfterReportTransmission(t *testing.T) {
	for _, crossing := range []string{"entity-restart", "setup-replacement", "association-release"} {
		t.Run(crossing, func(t *testing.T) {
			conn, assoc, _, peer := downlinkFixture(t, true)
			conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 12, DownlinkVolume: 8}}
			session := NewSession(11, 77, "", "", false)
			session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
			session.NewUrr(9, 1, ebpf.UrrInfo{})
			assoc.Sessions[11] = session
			assoc.sessionEntities[11] = session.CPFSEIDIPv4.String()
			conn.indexSession(assoc, session, 1)
			stamp := time.Unix(1700000000, 0)
			assoc.recoveries[session.CPFSEIDIPv4.String()] = stamp
			before := counterValue(t, PfcpUndeliveredUsage)
			if _, err := conn.ReleaseSessionByID(11); err != nil {
				t.Fatal(err)
			}
			report := identityRead(t, peer).(*message.SessionReportRequest)
			switch crossing {
			case "entity-restart":
				conn.Handle(protocolWire(t, message.NewHeartbeatRequest(5, ie.NewRecoveryTimeStamp(stamp.Add(time.Second)))), peer.LocalAddr().(*net.UDPAddr))
			case "setup-replacement":
				conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(5, ie.NewNodeIDFQDN(assoc.ID), ie.NewRecoveryTimeStamp(stamp))), peer.LocalAddr().(*net.UDPAddr))
			case "association-release":
				conn.Handle(protocolWire(t, message.NewAssociationReleaseRequest(5, ie.NewNodeIDFQDN(assoc.ID))), peer.LocalAddr().(*net.UDPAddr))
			}
			_ = identityRead(t, peer)
			for range 2 {
				conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
			}
			conn.serviceLocalSessionReleases()
			if len(conn.localReleases) != 0 || len(conn.transport.pending) != 0 || counterValue(t, PfcpUndeliveredUsage)-before != 20 {
				t.Fatal("terminal context crossing lost or counted usage twice")
			}
		})
	}
}

func TestLocalReleaseCrossingRequestsFromAdditionalCPAddress(t *testing.T) {
	conn, assoc, _, peer := downlinkFixture(t, true)
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
	assoc.Sessions[11] = session
	if _, err := conn.ReleaseSessionByID(11); err != nil {
		t.Fatal(err)
	}
	report := identityRead(t, peer).(*message.SessionReportRequest)
	additional := identityPeer(t, "127.0.0.94", 0)
	for _, request := range []message.Message{message.NewSessionModificationRequest(11, 5), message.NewSessionDeletionRequest(11, 6)} {
		conn.Handle(protocolWire(t, request), additional.LocalAddr().(*net.UDPAddr))
		response := identityRead(t, additional)
		if pipelineCause(t, response) != ie.CauseSessionContextNotFound || response.SEID() != 0 {
			t.Fatal("crossing request did not identify deleted context")
		}
	}
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
	if conn.addressIndex[session.CPFSEIDIPv4.String()][assoc] != 0 {
		t.Fatal("completed delivery retained entity address reference")
	}
}

// TS 29.244 V20.1.0 table 7.5.8.1-1 and clause 6.3.5.2.
func TestLocalReleasePSDBURequiresNegotiatedEPFAR(t *testing.T) {
	for _, cpSupport := range []bool{false, true} {
		for _, upSupport := range []bool{false, true} {
			for _, withUsage := range []bool{false, true} {
				t.Run(fmt.Sprintf("cp-%t-up-%t-usage-%t", cpSupport, upSupport, withUsage), func(t *testing.T) {
					conn, assoc, _, peer := downlinkFixture(t, true)
					assoc.CPFeatures = make([]byte, 2)
					assoc.UPFeatures = make([]byte, 6)
					if cpSupport {
						assoc.CPFeatures[0] = 1 << 2
					}
					if upSupport {
						assoc.UPFeatures[1] = 1 << 7
					}
					session := NewSession(11, 77, "", "", false)
					session.CPFSEIDIPv4 = peer.LocalAddr().(*net.UDPAddr).IP
					if withUsage {
						conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
						session.NewUrr(9, 1, ebpf.UrrInfo{})
					}
					assoc.Sessions[11] = session
					if _, err := conn.ReleaseSessionByID(11); err != nil {
						t.Fatal(err)
					}
					report := identityRead(t, peer).(*message.SessionReportRequest)
					if got := report.PFCPSRReqFlags.HasPSDBU(); got != (cpSupport && upSupport) {
						t.Fatalf("PSDBU=%t, negotiated=%t", got, cpSupport && upSupport)
					}
					if report.ReportType.HasUSAR() != withUsage || report.ReportType.HasUISR() == withUsage {
						t.Fatal("final report kind changed with negotiation")
					}
				})
			}
		}
	}
}
