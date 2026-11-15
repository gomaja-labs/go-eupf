package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestLocalReleaseCanReportDenseURRSession(t *testing.T) {
	conn, assoc, _, peer := downlinkFixture(t, true)
	conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 1}}
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.92")
	const count = 8192 // Fits the default URR map; crossed the old fixed metadata budget.
	for id := uint32(1); id <= count; id++ {
		session.NewUrr(id, id, ebpf.UrrInfo{})
	}
	assoc.Sessions[11] = session
	if _, err := conn.ReleaseSessionByID(11); err != nil {
		t.Fatal("valid dense session cannot enter local release", err)
	}
	seen := make(map[uint32]bool, count)
	for {
		report := identityRead(t, peer).(*message.SessionReportRequest)
		if report.MarshalLen() > 16000 {
			t.Fatal("report exceeded the bounded payload")
		}
		for _, field := range report.UsageReport {
			usage, err := field.UsageReportWithinSessionReportRequest()
			if err != nil {
				t.Fatal(err)
			}
			id, err := usage.URRID.URRID()
			if err != nil || id == 0 || id > count || seen[id] {
				t.Fatal("invalid or repeated URR", id, err)
			}
			seen[id] = true
		}
		last := report.PFCPSRReqFlags.HasPSDBU()
		if last != (len(seen) == count) {
			t.Fatal("PSDBU did not identify exactly the last batch")
		}
		conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), peer.LocalAddr().(*net.UDPAddr))
		conn.serviceLocalSessionReleases()
		if last {
			break
		}
	}
	if len(seen) != count || len(conn.localReleases) != 0 {
		t.Fatal("dense release retained state or lost reports")
	}
}
