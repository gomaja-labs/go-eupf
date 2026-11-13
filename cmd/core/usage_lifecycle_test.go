package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 tables 7.5.8.3-1, 7.5.5.2-1 and 7.5.7.2-1.
func TestUsageReportsIncludeMeasurementStart(t *testing.T) {
	for _, kind := range []string{"threshold", "remove URR", "last PDR", "delete session"} {
		t.Run(kind, func(t *testing.T) {
			conn := newProtocolConnection(t)
			maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
			conn.mapOperations = maps
			associationSetup(t, conn, "127.0.0.1", 1)
			s := NewSession(2, 42, "", "", false)
			s.CPFSEIDIPv4 = net.ParseIP("127.0.0.1")
			before := time.Now().Truncate(time.Second)
			s.NewUrr(11, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
			urr := s.URRs[11]
			if urr.windowStart.Before(before) || urr.windowStart.After(time.Now()) {
				t.Fatal("URR creation did not start its measurement window")
			}
			urr.windowStart = before.Add(-10 * time.Minute)
			wantStart := before.Add(-20 * time.Minute)
			urr.unreportedStart, urr.UnreportedUplink = wantStart, 5
			s.URRs[11] = urr
			s.PutPDR(1, SPDRInfo{PdrID: 1, Teid: 10, URRIDs: []uint32{11}, PdrInfo: ebpf.PdrInfo{SessionID: 2, PdrID: 1, UrrIDs: []uint32{1}}})
			conn.GetAssociation("127.0.0.1").Sessions[2] = s
			var start, end *ie.IE
			switch kind {
			case "threshold":
				conn.SendReports()
				for _, pending := range conn.transport.pending {
					msg, err := message.Parse(pending.wire)
					if err != nil {
						t.Fatal(err)
					}
					fields, err := msg.(*message.SessionReportRequest).UsageReport[0].UsageReportWithinSessionReportRequest()
					if err != nil {
						t.Fatal(err)
					}
					start, end = fields.StartTime, fields.EndTime
				}
			case "remove URR", "last PDR":
				remove := ie.NewRemoveURR(ie.NewURRID(11))
				if kind == "last PDR" {
					remove = ie.NewRemovePDR(ie.NewPDRID(1))
				}
				reply, _, err := HandlePfcpSessionModificationRequest(conn, message.NewSessionModificationRequest(2, 2, remove), "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				response := reply.(*message.SessionModificationResponse)
				if len(response.UsageReport) != 1 {
					t.Fatalf("reports=%d", len(response.UsageReport))
				}
				fields, err := response.UsageReport[0].UsageReportWithinSessionModificationResponse()
				if err != nil {
					t.Fatal(err)
				}
				start, end = fields.StartTime, fields.EndTime
			case "delete session":
				reply, _, err := HandlePfcpSessionDeletionRequest(conn, message.NewSessionDeletionRequest(2, 2), "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				response := reply.(*message.SessionDeletionResponse)
				if len(response.UsageReport) != 1 {
					t.Fatalf("reports=%d", len(response.UsageReport))
				}
				fields, err := response.UsageReport[0].UsageReportWithinSessionDeletionResponse()
				if err != nil {
					t.Fatal(err)
				}
				start, end = fields.StartTime, fields.EndTime
			}
			if start == nil || end == nil {
				t.Fatal("measurement interval is missing Start Time or End Time")
			}
			from, err := start.StartTime()
			if err != nil {
				t.Fatal(err)
			}
			to, err := end.EndTime()
			if err != nil {
				t.Fatal(err)
			}
			if !from.Equal(wantStart) || from.After(to) || to.After(time.Now()) {
				t.Fatalf("invalid interval %v .. %v", from, to)
			}
		})
	}
}

func usageWindow(t *testing.T, conn *PfcpConnection, sequence uint32) (time.Time, time.Time, *pendingRequest) {
	t.Helper()
	for _, pending := range conn.transport.pending {
		msg, err := message.Parse(pending.wire)
		if err != nil {
			t.Fatal(err)
		}
		report, ok := msg.(*message.SessionReportRequest)
		if !ok || len(report.UsageReport) != 1 {
			continue
		}
		fields, err := report.UsageReport[0].UsageReportWithinSessionReportRequest()
		if err != nil {
			t.Fatal(err)
		}
		seq, err := fields.URSEQN.URSEQN()
		if err != nil {
			t.Fatal(err)
		}
		if seq != sequence {
			continue
		}
		start, err := fields.StartTime.StartTime()
		if err != nil {
			t.Fatal(err)
		}
		end, err := fields.EndTime.EndTime()
		if err != nil {
			t.Fatal(err)
		}
		return start, end, pending
	}
	t.Fatalf("no usage window with UR-SEQN %d", sequence)
	return time.Time{}, time.Time{}, nil
}

func TestUsageWindowRolloverPreservesEarliestUndeliveredStart(t *testing.T) {
	for _, outcome := range []requestOutcome{requestAccepted, requestRejected, requestInvalid, requestTimeout, requestCanceled} {
		t.Run(string(outcome), func(t *testing.T) {
			conn := newProtocolConnection(t)
			maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
			conn.mapOperations = maps
			associationSetup(t, conn, "127.0.0.1", 1)
			s := NewSession(2, 42, "", "", false)
			s.CPFSEIDIPv4 = net.ParseIP("127.0.0.1")
			s.NewUrr(11, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
			a := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
			urr := s.URRs[11]
			urr.windowStart = a
			s.URRs[11] = urr
			conn.GetAssociation("127.0.0.1").Sessions[2] = s
			conn.SendReports()
			start, end, first := usageWindow(t, conn, 0)
			if !start.Equal(a) || !s.URRs[11].windowStart.Truncate(time.Second).Equal(end) {
				t.Fatal("first window did not start at creation or advance to report end")
			}
			b := a.Add(5 * time.Minute)
			urr = s.URRs[11]
			urr.windowStart = b
			s.URRs[11] = urr
			maps.urr.UplinkVolume = 40
			conn.SendReports()
			start, end, second := usageWindow(t, conn, 1)
			if !start.Equal(b) {
				t.Fatalf("next window starts %v, want %v", start, b)
			}
			// Later completion before earlier completion must not overwrite the oldest start.
			if outcome == requestRejected {
				conn.completeReportLocked(first, s, requestResult{outcome: outcome})
				conn.completeReportLocked(second, s, requestResult{outcome: outcome})
			} else {
				conn.completeReportLocked(second, s, requestResult{outcome: outcome})
				conn.completeReportLocked(first, s, requestResult{outcome: outcome})
			}
			maps.urr.UplinkVolume = 50
			conn.SendReports()
			start, _, _ = usageWindow(t, conn, 2)
			want := a
			if outcome == requestAccepted {
				want = end
			}
			if !start.Equal(want) {
				t.Fatalf("merged window starts %v, want %v", start, want)
			}
			if !s.URRs[11].unreportedStart.IsZero() {
				t.Fatal("admitted report retained the old debt timestamp")
			}
		})
	}
}

func TestUsageAdmissionFailureDoesNotAdvanceMeasurementStart(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.maxOriginatedRequests = 1
	conn.transport.pending = map[uint32]*pendingRequest{1: {}}
	conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
	associationSetup(t, conn, "127.0.0.1", 1)
	s := NewSession(2, 42, "", "", false)
	s.CPFSEIDIPv4 = net.ParseIP("127.0.0.1")
	s.NewUrr(11, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
	before := s.URRs[11]
	conn.GetAssociation("127.0.0.1").Sessions[2] = s
	conn.SendReports()
	if got := s.URRs[11]; got != before {
		t.Fatalf("failed admission changed measurement: %+v -> %+v", before, got)
	}
}

func TestFinalUsageReportsStartAtZeroPerURR(t *testing.T) {
	for _, profile := range []PfcpProfile{DefaultProfile{}, HuaweiProfile{}} {
		conn, peer := PreparePfcpConnectionWithMockAndProfile(t, &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 99}}, config.UpfConfig{}, profile)
		session := NewSession(2, 42, "", "", false)
		session.NewUrr(11, 1, ebpf.UrrInfo{})
		session.NewUrr(22, 2, ebpf.UrrInfo{})
		conn.GetAssociation(peer).Sessions[2] = session
		reply, _, err := HandlePfcpSessionDeletionRequest(conn, message.NewSessionDeletionRequest(2, 1), peer)
		if err != nil {
			t.Fatal(err)
		}
		response := reply.(*message.SessionDeletionResponse)
		cause, err := response.Cause.Cause()
		if err != nil || cause != ie.CauseRequestAccepted {
			t.Fatalf("cause=%d err=%v", cause, err)
		}
		if len(response.UsageReport) != 2 {
			t.Fatalf("reports=%d", len(response.UsageReport))
		}
		for _, report := range response.UsageReport {
			fields, err := report.UsageReportWithinSessionDeletionResponse()
			if err != nil {
				t.Fatal(err)
			}
			seq, err := fields.URSEQN.URSEQN()
			if err != nil || seq != 0 {
				t.Fatalf("first per-URR sequence=%d err=%v profile=%T", seq, err, profile)
			}
			if !fields.UsageReportTrigger.HasTERMR() {
				t.Fatal("missing termination trigger")
			}
		}
	}
}

func TestUsagePollPreservesUnreportedOctets(t *testing.T) {
	maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 5}}
	conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{})
	session := NewSession(2, 42, "", "", false)
	session.NewUrr(11, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
	conn.GetAssociation(peer).Sessions[2] = session
	conn.SendReports()
	if got := session.URRs[11].UrrInfo.UplinkVolume; got != 0 {
		t.Fatalf("poll discarded %d unreported octets", got)
	}
	maps.urr.UplinkVolume = 7
	conn.SendReports()
	if got := session.URRs[11].UrrInfo.UplinkVolume; got != 0 {
		t.Fatalf("second poll discarded %d unreported octets", got)
	}
}

func TestUsageReportCapacityKeepsUnreportedUsage(t *testing.T) {
	maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
	conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{})
	conn.maxOriginatedRequests = 1
	conn.transport.pending = map[uint32]*pendingRequest{1: {}}
	s := NewSession(2, 42, "", "", false)
	s.CPFSEIDIPv4 = net.ParseIP("127.0.0.1")
	s.NewUrr(11, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
	conn.GetAssociation(peer).Sessions[2] = s
	conn.SendReports()
	if got := s.URRs[11]; got.ReportSeqNumber != 0 || got.UrrInfo.UplinkVolume != 0 || got.UrrInfo.VolumeThreshold != 10 {
		t.Fatalf("transport rejection lost usage: %+v", got)
	}
}

func TestUsageThresholdReappliesForEveryMeasurementWindow(t *testing.T) {
	conn := newProtocolConnection(t)
	maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
	conn.mapOperations = maps
	associationSetup(t, conn, "127.0.0.1", 1)
	s := NewSession(2, 42, "", "", false)
	s.CPFSEIDIPv4 = net.ParseIP("127.0.0.1")
	s.NewUrr(11, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
	conn.GetAssociation("127.0.0.1").Sessions[2] = s
	conn.SendReports()
	if got := s.URRs[11].UrrInfo.VolumeThreshold; got != 10 {
		t.Fatalf("report erased configured threshold: %d", got)
	}
	maps.urr.UplinkVolume = 30
	conn.SendReports()
	if len(conn.transport.pending) != 2 || s.URRs[11].ReportSeqNumber != 2 {
		t.Fatal("next threshold window did not report without reconfiguration")
	}
	conn.SendReports()
	if len(conn.transport.pending) != 2 {
		t.Fatal("unchanged counters generated duplicate usage")
	}
	maps.urr.UplinkVolume = 39
	conn.SendReports()
	if len(conn.transport.pending) != 2 {
		t.Fatal("usage below the next threshold generated a report")
	}
	maps.urr.UplinkVolume = 40
	conn.SendReports()
	if len(conn.transport.pending) != 3 || s.URRs[11].ReportSeqNumber != 3 {
		t.Fatal("third threshold window did not report")
	}
}

func TestLastPDRRemovalReportsAndResetsRetainedURR(t *testing.T) {
	maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 99}}
	conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{})
	s := NewSession(2, 42, "", "", false)
	s.CPFSEIDIPv4 = net.ParseIP("127.0.0.1")
	s.NewUrr(11, 1, ebpf.UrrInfo{UplinkVolume: 4, VolumeThreshold: 10, VolumeTrigger: true})
	urr := s.URRs[11]
	urr.windowStart = time.Now().Add(-time.Hour)
	s.URRs[11] = urr
	s.PutPDR(1, SPDRInfo{PdrID: 1, Teid: 10, URRIDs: []uint32{11}, PdrInfo: ebpf.PdrInfo{SessionID: 2, PdrID: 1, UrrIDs: []uint32{1}}})
	conn.GetAssociation(peer).Sessions[2] = s
	beforeReset := time.Now()
	reply, _, err := HandlePfcpSessionModificationRequest(conn, message.NewSessionModificationRequest(2, 1, ie.NewRemovePDR(ie.NewPDRID(1))), peer)
	if err != nil {
		t.Fatal(err)
	}
	response := reply.(*message.SessionModificationResponse)
	cause, _ := response.Cause.Cause()
	if cause != 1 {
		t.Fatal(cause)
	}
	if len(response.UsageReport) != 1 {
		t.Fatal("last PDR removal omitted non-null final usage")
	}
	report, _ := response.UsageReport[0].UsageReportWithinSessionModificationResponse()
	volume, _ := report.VolumeMeasurement.VolumeMeasurement()
	if volume.TotalVolume != 95 {
		t.Fatal(volume.TotalVolume)
	}
	retained := conn.GetAssociation(peer).Sessions[2].URRs[11]
	if retained.windowStart.Before(beforeReset) || !retained.unreportedStart.IsZero() {
		t.Fatal("counter reset did not begin a fresh measurement window")
	}
	if retained.GlobalId != 1 || retained.ReportSeqNumber != 1 || retained.UrrInfo.UplinkVolume != 0 || maps.urr.UplinkVolume != 0 {
		t.Fatalf("URR not retained and reset: %+v counters=%+v", retained, maps.urr)
	}
}

func TestActivatingVolumeTriggerRequiresThreshold(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	s := NewSession(2, 42, "", "", false)
	s.CPFSEIDIPv4 = net.ParseIP("127.0.0.1")
	s.NewUrr(11, 1, ebpf.UrrInfo{})
	conn.GetAssociation(peer).Sessions[2] = s
	reply, _, err := HandlePfcpSessionModificationRequest(conn, message.NewSessionModificationRequest(2, 1, ie.NewUpdateURR(ie.NewURRID(11), ie.NewReportingTriggers(2, 0))), peer)
	if err != nil {
		t.Fatal(err)
	}
	response := reply.(*message.SessionModificationResponse)
	cause, _ := response.Cause.Cause()
	if cause != ie.CauseConditionalIEMissing {
		t.Fatalf("missing threshold cause=%d", cause)
	}
}
