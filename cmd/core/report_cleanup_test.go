package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// Two Session Report Responses with Cause 65 for one session are serviced in
// one maintenance pass (bundle, or the first cleanup waiting for capacity).
// Every rejected octet must appear in the final report or the undelivered count.
func TestContextNotFoundReportsRetainEveryUsageWindow(t *testing.T) {
	for _, path := range []string{"same-pass", "capacity-deferral"} {
		t.Run(path, func(t *testing.T) { contextNotFoundUsageWindows(t, path == "capacity-deferral") })
	}
}

func contextNotFoundUsageWindows(t *testing.T, deferByCapacity bool) {
	conn := newProtocolConnection(t)
	maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
	conn.mapOperations = maps
	cp := identityPeer(t, "127.0.0.27", 8805)
	identitySetup(t, conn, cp, "lost.example")
	assoc := conn.associationByID("lost.example")
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.27")
	session.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 10})
	session.NewUrr(10, 2, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 10})
	assoc.Sessions[11] = session
	before := counterValue(t, PfcpUndeliveredUsage)
	conn.SendReports()
	first, second := identityRead(t, cp), identityRead(t, cp)
	if deferByCapacity {
		// Run-loop order: one service pass after each datagram. The first
		// cleanup finds local-release capacity exhausted and is requeued.
		conn.localReleaseLimit = 1
		conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseSessionContextNotFound))), cp.LocalAddr().(*net.UDPAddr))
		conn.serviceHeartbeats(time.Now())
		if assoc.Sessions[11] == nil {
			t.Fatal("capacity did not defer the first cleanup")
		}
		conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, second.Sequence(), ie.NewCause(ie.CauseSessionContextNotFound))), cp.LocalAddr().(*net.UDPAddr))
		conn.localReleaseLimit = 0
		conn.serviceHeartbeats(time.Now().Add(200 * time.Millisecond))
	} else {
		for _, request := range []message.Message{first, second} {
			conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, request.Sequence(), ie.NewCause(ie.CauseSessionContextNotFound))), cp.LocalAddr().(*net.UDPAddr))
		}
		conn.serviceHeartbeats(time.Now())
	}
	conn.serviceLocalSessionReleases()
	final := identityRead(t, cp).(*message.SessionReportRequest)
	var reported uint64
	for _, item := range final.UsageReport {
		fields, err := item.UsageReportWithinSessionReportRequest()
		if err != nil {
			t.Fatal(err)
		}
		volume, err := fields.VolumeMeasurement.VolumeMeasurement()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := fields.URRID.URRID()
		t.Logf("final report URR %d uplink %d", id, volume.UplinkVolume)
		reported += volume.UplinkVolume
	}
	lost := uint64(counterValue(t, PfcpUndeliveredUsage) - before)
	t.Logf("final reported=%d undelivered counted=%d (40 rejected octets)", reported, lost)
	if reported != 40 || lost != 0 {
		t.Fatalf("rejected usage neither reported nor counted: reported=%d counted=%d want 40", reported, lost)
	}
}

func TestContextNotFoundCleanupCountsDetachedUsageOnce(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed-session", true: "replaced-association"}[replaced], func(t *testing.T) {
			conn := newProtocolConnection(t)
			peer := identityPeer(t, "127.0.0.27", 0)
			identitySetup(t, conn, peer, "lost.example")
			assoc := conn.associationByID("lost.example")
			session := NewSession(11, 77, "", "", false)
			assoc.Sessions[11] = session
			if replaced {
				conn.NodeAssociations[assoc.ID] = &NodeAssociation{ID: assoc.ID}
			} else {
				delete(assoc.Sessions, 11)
			}
			before := counterValue(t, PfcpUndeliveredUsage)
			conn.reportCleanup = []reportCleanup{{request: &pendingRequest{association: assoc, localSEID: 11, usage: []reportedUsage{{id: 9, uplink: 12, downlink: 8}}}}}
			conn.serviceReportCleanupLocked(time.Now())
			conn.serviceReportCleanupLocked(time.Now())
			if got := counterValue(t, PfcpUndeliveredUsage) - before; got != 20 {
				t.Fatalf("undelivered octets=%g want 20", got)
			}
		})
	}
}
