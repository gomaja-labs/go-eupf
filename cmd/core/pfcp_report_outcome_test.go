package core

import (
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestFailedUsageReportIsIncludedInNextReport(t *testing.T) {
	for _, outcome := range []string{"rejected", "timeout", "accepted"} {
		t.Run(outcome, func(t *testing.T) {
			conn := newProtocolConnection(t)
			maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20, DownlinkVolume: 3}}
			conn.mapOperations = maps
			cp := identityPeer(t, "127.0.0.25", 8805)
			identitySetup(t, conn, cp, "usage.example")
			assoc := conn.associationByID("usage.example")
			session := NewSession(11, 77, "", "", false)
			session.CPFSEIDIPv4 = net.ParseIP("127.0.0.25")
			session.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 10})
			assoc.Sessions[11] = session
			conn.requestTimeout = time.Millisecond
			conn.SendReports()
			first := identityRead(t, cp).(*message.SessionReportRequest)
			if outcome == "timeout" {
				conn.serviceTransactions(time.Now().Add(time.Second))
			} else {
				cause := ie.CauseRequestAccepted
				if outcome == "rejected" {
					cause = ie.CauseSystemFailure
				}
				conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(cause))), cp.LocalAddr().(*net.UDPAddr))
			}
			maps.urr.UplinkVolume = 35
			urr := session.URRs[9]
			urr.UrrInfo.VolumeReported = false
			session.URRs[9] = urr
			conn.SendReports()
			next := identityRead(t, cp).(*message.SessionReportRequest)
			fields, err := next.UsageReport[0].UsageReportWithinSessionReportRequest()
			if err != nil {
				t.Fatal(err)
			}
			volume, err := fields.VolumeMeasurement.VolumeMeasurement()
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(38)
			if outcome == "accepted" {
				want = 15
			}
			if volume.TotalVolume != want {
				t.Fatalf("next report total %d, want %d", volume.TotalVolume, want)
			}
		})
	}
}

func TestReportContextNotFoundDeletesOnlyOriginalSession(t *testing.T) {
	conn := newProtocolConnection(t)
	cp := identityPeer(t, "127.0.0.26", 8805)
	identitySetup(t, conn, cp, "report.example")
	assoc := conn.associationByID("report.example")
	for _, id := range []uint64{11, 12} {
		s := NewSession(id, 77, "", "", false)
		s.CPFSEIDIPv4 = net.ParseIP("127.0.0.26")
		assoc.Sessions[id] = s
	}
	report := message.NewSessionReportRequest(77, 0, ie.NewReportType(0, 0, 0, 1))
	if err := conn.sendAssociationRequest(report, assoc.ID, false, 12); err != nil {
		t.Fatal(err)
	}
	_ = identityRead(t, cp)
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(12, report.Sequence(), ie.NewCause(ie.CauseSessionContextNotFound))), cp.LocalAddr().(*net.UDPAddr))
	conn.serviceHeartbeats(time.Now())
	if assoc.Sessions[12] != nil || assoc.Sessions[11] == nil {
		t.Fatal("context-not-found did not remove exactly the original session")
	}
}

func TestFailedUsageReportAfterSessionDeletionIsCounted(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.requestTimeout = time.Millisecond
	conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
	cp := identityPeer(t, "127.0.0.41", 8805)
	identitySetup(t, conn, cp, "usage.example")
	assoc := conn.associationByID("usage.example")
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.41")
	session.NewUrr(9, 1, ebpf.UrrInfo{VolumeThreshold: 10, VolumeTrigger: true})
	assoc.Sessions[11] = session
	conn.SendReports()
	_ = identityRead(t, cp)
	registry := prometheus.NewRegistry()
	if err := registry.Register(PfcpReportFailures); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(PfcpUndeliveredUsage); err != nil {
		t.Fatal(err)
	}
	counts := func() (float64, float64) {
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		var failed, lost float64
		for _, family := range families {
			for _, metric := range family.GetMetric() {
				if family.GetName() == "upf_pfcp_undelivered_usage_octets_total" {
					lost = metric.GetCounter().GetValue()
				}
				if family.GetName() == "upf_pfcp_report_failures_total" {
					for _, label := range metric.GetLabel() {
						if label.GetName() == "outcome" && label.GetValue() == string(requestTimeout) {
							failed = metric.GetCounter().GetValue()
						}
					}
				}
			}
		}
		return failed, lost
	}
	beforeFailures, beforeLost := counts()
	delete(assoc.Sessions, 11)
	conn.serviceTransactions(time.Now().Add(time.Second))
	afterFailures, afterLost := counts()
	if afterFailures-beforeFailures != 1 || afterLost-beforeLost != 20 {
		t.Fatal("late failure silently discarded usage after deletion")
	}
}
