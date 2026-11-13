package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

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
	s.PutPDR(1, SPDRInfo{PdrID: 1, Teid: 10, URRIDs: []uint32{11}, PdrInfo: ebpf.PdrInfo{SessionID: 2, PdrID: 1, UrrIDs: []uint32{1}}})
	conn.GetAssociation(peer).Sessions[2] = s
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
