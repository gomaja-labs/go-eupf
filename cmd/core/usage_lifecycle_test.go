package core

import (
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
		conn.NodeAssociations[peer].Sessions[2] = session
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
	conn.NodeAssociations[peer].Sessions[2] = session
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
	conn.maxTransactions = 1
	conn.transport.pending = map[uint32]*pendingRequest{1: {}}
	s := NewSession(2, 42, "", "", false)
	s.NewUrr(11, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
	conn.NodeAssociations[peer].Sessions[2] = s
	conn.SendReports()
	if got := s.URRs[11]; got.ReportSeqNumber != 0 || got.UrrInfo.UplinkVolume != 0 || got.UrrInfo.VolumeThreshold != 10 {
		t.Fatalf("transport rejection lost usage: %+v", got)
	}
}

func TestUsageThresholdKeepsConfigurationAndRearmsExplicitly(t *testing.T) {
	conn := newProtocolConnection(t)
	maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
	conn.mapOperations = maps
	associationSetup(t, conn, "127.0.0.1", 1)
	s := NewSession(2, 42, "", "", false)
	s.NewUrr(11, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
	conn.NodeAssociations["127.0.0.1"].Sessions[2] = s
	conn.SendReports()
	if got := s.URRs[11].UrrInfo.VolumeThreshold; got != 10 {
		t.Fatalf("report erased configured threshold: %d", got)
	}
	maps.urr.UplinkVolume = 30
	conn.SendReports()
	if len(conn.transport.pending) != 1 {
		t.Fatal("threshold reported twice without reconfiguration")
	}
	configured := s.URRs[11]
	updateUrr(&configured.UrrInfo, ie.NewUpdateURR(ie.NewURRID(11), ie.NewVolumeThreshold(1, 10, 0, 0)))
	s.URRs[11] = configured
	conn.SendReports()
	if len(conn.transport.pending) != 2 || s.URRs[11].ReportSeqNumber != 2 {
		t.Fatal("new threshold did not rearm reporting")
	}
}
