package core

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 table 7.5.4.1-1 and clause 6.3.5.3: failure
// at a superseded CP F-SEID says nothing about the current session context.
func TestFailedReportFollowsCurrentCPFSEID(t *testing.T) {
	for _, origin := range []string{"release_id", "release_user", "release", "usage", "adc", "dldr", "queued", "threshold"} {
		for _, order := range []string{"change_first", "answer_first"} {
			for _, failure := range []string{"context_not_found", "rejected", "timeout"} {
				t.Run(origin+"/"+order+"/"+failure, func(t *testing.T) {
					conn := newProtocolConnection(t)
					maps := &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
					conn.mapOperations = maps
					cp := identityPeer(t, "127.0.0.25", 8805)
					nextCP := identityPeer(t, "127.0.0.26", 8805)
					identitySetup(t, conn, cp, "handover.example")
					assoc := conn.associationByID("handover.example")
					s := NewSession(11, 77, "001010000000017", "", false)
					s.CPFSEIDIPv4 = net.ParseIP("127.0.0.25")
					s.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 10})
					assoc.Sessions[11] = s
					conn.requestTimeout = time.Millisecond
					switch origin {
					case "release_id":
						if !conn.ReleaseSessionByID(11) {
							t.Fatal("missing session")
						}
					case "release_user":
						if !conn.ReleaseSessionByUserID(s.IMSI, "") {
							t.Fatal("missing subscriber")
						}
					case "release":
						SendSessionReportSessionRelease(conn, 11, 0, assoc.ID, false, []uint16{1})
					case "usage":
						SendSessionReportUsage(conn, 11, 0, assoc.ID, 9, 0, 20, 0, false)
					case "adc":
						SendSessionReportADC(conn, 11, 0, assoc.ID, 9, 0, "permit out ip from any to any", false)
					case "dldr":
						SendDownlinkNotificationReport(conn, 11, 0, assoc.ID, 1, false)
					case "queued":
						conn.sendQueued([]queuedMessage{{msg: message.NewSessionReportRequest(77, 0, ie.NewReportType(0, 0, 0, 1)), association: assoc.ID, localSEID: 11}})
					case "threshold":
						conn.SendReports()
					}
					first := identityRead(t, cp).(*message.SessionReportRequest)
					change := func() {
						conn.Handle(protocolWire(t, message.NewSessionModificationRequest(11, 900, ie.NewFSEID(88, net.ParseIP("127.0.0.26"), nil))), cp.LocalAddr().(*net.UDPAddr))
						if cause := pipelineCause(t, identityRead(t, cp)); cause != ie.CauseRequestAccepted {
							t.Fatalf("change cause %d", cause)
						}
					}
					answer := func() {
						if failure == "timeout" {
							conn.serviceTransactions(time.Now().Add(time.Second))
						} else {
							cause := ie.CauseSessionContextNotFound
							if failure == "rejected" {
								cause = ie.CauseSystemFailure
							}
							conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(cause))), cp.LocalAddr().(*net.UDPAddr))
						}
					}
					if order == "change_first" {
						change()
						answer()
					} else {
						answer()
						change()
					}
					conn.serviceHeartbeats(time.Now())
					if assoc.Sessions[11] == nil {
						t.Fatal("former CP failure deleted current session")
					}
					// For an already failed transfer, a later change must preserve the
					// octets. Immediate re-origination applies when change preceded failure.
					if order == "answer_first" && failure != "context_not_found" {
						return
					}
					second, ok := pipelineRead(t, nextCP, 100*time.Millisecond).(*message.SessionReportRequest)
					if !ok {
						t.Fatal("failed report was not re-originated to current CP")
					}
					if second.Sequence() == first.Sequence() || second.SEID() != 88 {
						t.Fatal("new request did not get current SEID and a new sequence")
					}
					first.Header.SEID, first.Header.SequenceNumber = second.SEID(), second.Sequence()
					if !bytes.Equal(protocolWire(t, first), protocolWire(t, second)) {
						t.Fatal("re-originated report changed information")
					}
					conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, second.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), nextCP.LocalAddr().(*net.UDPAddr))
					if len(conn.transport.pending) != 0 {
						t.Fatal("report did not complete")
					}
				})
			}
		}
	}
}

func TestFailedReportUsageSurvivesCounterSlotSwap(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained", true: "recreated"}[recreate], func(t *testing.T) {
			conn := newProtocolConnection(t)
			conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
			cp := identityPeer(t, "127.0.0.25", 8805)
			identitySetup(t, conn, cp, "usage.example")
			assoc := conn.associationByID("usage.example")
			s := NewSession(11, 77, "", "", false)
			s.CPFSEIDIPv4 = net.ParseIP("127.0.0.25")
			s.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 10})
			assoc.Sessions[11] = s
			conn.SendReports()
			report := identityRead(t, cp)
			if recreate {
				if _, err := s.RemoveUrr(9); err != nil {
					t.Fatal(err)
				}
				s.NewUrr(9, 1, ebpf.UrrInfo{})
			} else {
				urr := s.URRs[9]
				urr.GlobalId = 2
				s.URRs[9] = urr
			}
			conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseSystemFailure))), cp.LocalAddr().(*net.UDPAddr))
			want := uint64(20)
			if recreate {
				want = 0
			}
			if got := s.URRs[9].UnreportedUplink; got != want {
				t.Fatalf("restored octets %d want %d", got, want)
			}
		})
	}
}
