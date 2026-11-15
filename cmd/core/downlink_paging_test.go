package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestDownlinkReportCarriesTheTriggeringPacketDSCP(t *testing.T) {
	for _, is5G := range []bool{false, true} {
		for _, dscp := range []uint8{0, 7, 8, 63} {
			t.Run(fmt.Sprintf("5GC=%t/DSCP=%d", is5G, dscp), func(t *testing.T) {
				conn, _, session, peer := downlinkFixture(t, is5G)
				conn.stateMu.Lock()
				conn.noteDownlinkPacketLocked(session, 1, ebpf.BufferRecord{SessionID: 11, Cookie: 7, PDRID: 9, QFI: 0, QFIPresent: true, PPI: dscp, Notify: true}, time.Now())
				conn.stateMu.Unlock()
				conn.serviceDownlinkNotifications(time.Now())
				report := identityRead(t, peer).(*message.SessionReportRequest)
				fields, err := report.DownlinkDataReport.DownlinkDataReport()
				if err != nil || len(fields.DownlinkDataServiceInformation) != 1 {
					t.Fatalf("missing paging service information: %v", err)
				}
				service, err := fields.DownlinkDataServiceInformation[0].DownlinkDataServiceInformation()
				if err != nil || service.Flags&1 == 0 || service.PagingPolicyIndication != dscp || (service.Flags&2 != 0) != is5G || service.QFI != 0 {
					t.Fatalf("paging service=%+v error=%v want DSCP=%d", service, err, dscp)
				}
			})
		}
	}
}
