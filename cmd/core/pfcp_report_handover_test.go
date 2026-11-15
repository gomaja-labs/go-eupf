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
	for _, origin := range []string{"usage", "adc", "dldr", "queued", "threshold"} {
		for _, order := range []string{"change_first", "answer_first"} {
			for _, failure := range []string{"context_not_found", "rejected", "timeout"} {
				for _, changeMode := range []string{"seid", "address", "both"} {
					t.Run(origin+"/"+order+"/"+failure+"/"+changeMode, func(t *testing.T) {
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
						case "usage":
							SendSessionReportUsage(conn, 11, 0, assoc.ID, 9, 0, 20, 0, time.Now(), false)
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
						newSEID := uint64(88)
						newIP := "127.0.0.26"
						destination := nextCP
						if changeMode == "seid" {
							newIP = "127.0.0.25"
							destination = cp
						}
						if changeMode == "address" {
							newSEID = 77
						}
						change := func() {
							conn.Handle(protocolWire(t, message.NewSessionModificationRequest(11, 900, ie.NewFSEID(newSEID, net.ParseIP(newIP), nil))), cp.LocalAddr().(*net.UDPAddr))
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
						second, ok := pipelineRead(t, destination, 100*time.Millisecond).(*message.SessionReportRequest)
						if !ok {
							t.Fatal("failed report was not re-originated to current CP")
						}
						if second.Sequence() == first.Sequence() || second.SEID() != newSEID {
							t.Fatal("new request did not get current SEID and a new sequence")
						}
						first.Header.SEID, first.SequenceNumber = second.SEID(), second.Sequence()
						if !bytes.Equal(protocolWire(t, first), protocolWire(t, second)) {
							t.Fatal("re-originated report changed information")
						}
						conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, second.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), destination.LocalAddr().(*net.UDPAddr))
						if len(conn.transport.pending) != 0 {
							t.Fatal("report did not complete")
						}
					})
				}
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

func TestFailedUsageReportSurvivesLastPDRDissociation(t *testing.T) {
	conn := newProtocolConnection(t)
	plane := &delayedUsagePlane{MapOperationsMock: MapOperationsMock{nextID: 1, urr: ebpf.UrrInfo{UplinkVolume: 20}}}
	conn.mapOperations = plane
	cp := identityPeer(t, "127.0.0.25", 8805)
	identitySetup(t, conn, cp, "detach.example")
	assoc := conn.associationByID("detach.example")
	s := NewSession(11, 77, "", "", false)
	s.CPFSEIDIPv4 = net.ParseIP("127.0.0.25")
	s.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 10})
	oldStart := time.Now().Add(-time.Hour).Truncate(time.Second)
	urr := s.URRs[9]
	urr.windowStart = oldStart
	s.URRs[9] = urr
	s.PDRs[1] = SPDRInfo{PdrID: 1, URRIDs: []uint32{9}, PdrInfo: ebpf.PdrInfo{UrrIDs: []uint32{1}}}
	assoc.Sessions[11] = s
	conn.SendReports()
	report := identityRead(t, cp)
	urr = s.URRs[9]
	urr.windowStart = oldStart.Add(30 * time.Minute)
	s.URRs[9] = urr
	beforeReplacement := time.Now()
	conn.Handle(protocolWire(t, message.NewSessionModificationRequest(11, 900, ie.NewRemovePDR(ie.NewPDRID(1)))), cp.LocalAddr().(*net.UDPAddr))
	current := assoc.Sessions[11]
	if current.URRs[9].windowStart.Before(beforeReplacement) {
		t.Fatal("counter replacement retained its old measurement window")
	}
	if len(current.PDRs) != 0 || current.URRs[9].GlobalId == 1 || current.URRs[9].generation != s.URRs[9].generation {
		t.Fatal("dissociation did not preserve URR identity across its counter swap")
	}
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseSystemFailure))), cp.LocalAddr().(*net.UDPAddr))
	if current.URRs[9].UnreportedUplink != 20 {
		t.Fatal("failed report debt disappeared during last-PDR dissociation")
	}
	if !current.URRs[9].measurementStart().Equal(oldStart) {
		t.Fatal("counter replacement lost the failed report's start")
	}
	plane.transaction.finish(t)
	if cause := pipelineCause(t, identityRead(t, cp)); cause != ie.CauseRequestAccepted {
		t.Fatalf("dissociation cause %d", cause)
	}
	plane.urr = ebpf.UrrInfo{}
	conn.SendReports()
	next := identityRead(t, cp).(*message.SessionReportRequest)
	fields, err := next.UsageReport[0].UsageReportWithinSessionReportRequest()
	if err != nil {
		t.Fatal(err)
	}
	start, err := fields.StartTime.StartTime()
	if err != nil || !start.Equal(oldStart) {
		t.Fatalf("restored start=%v err=%v, want %v", start, err, oldStart)
	}
	volume, err := fields.VolumeMeasurement.VolumeMeasurement()
	if err != nil || volume.UplinkVolume != 20 {
		t.Fatalf("retained URR's next usage %v: %v", volume, err)
	}
}

func TestAssociationRetentionPreservesPendingUsageDebt(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.mapOperations = &MapOperationsMock{urr: ebpf.UrrInfo{UplinkVolume: 20}}
	cp := identityPeer(t, "127.0.0.25", 0)
	entity := identityPeer(t, "127.0.0.26", 8805)
	identitySetup(t, conn, cp, "retention.example")
	s := NewSession(11, 77, "", "", false)
	s.CPFSEIDIPv4 = net.ParseIP("127.0.0.26")
	s.NewUrr(9, 1, ebpf.UrrInfo{VolumeTrigger: true, VolumeThreshold: 10})
	conn.associationByID("retention.example").Sessions[11] = s
	conn.SendReports()
	_ = identityRead(t, entity)
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(900, ie.NewNodeIDFQDN("retention.example"), ie.NewRecoveryTimeStamp(time.Now()), ie.NewPFCPSessionRetentionInformation())), cp.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, cp).(*message.AssociationSetupResponse)
	if !response.PFCPASRspFlags.HasPSREI() {
		t.Fatal("requested sessions were not retained")
	}
	current := conn.associationByID("retention.example").Sessions[11]
	if current != s || current.URRs[9].UnreportedUplink != 20 {
		t.Fatal("association replacement discarded pending octets of a retained URR")
	}
	conn.SendReports()
	next := identityRead(t, entity).(*message.SessionReportRequest)
	fields, err := next.UsageReport[0].UsageReportWithinSessionReportRequest()
	if err != nil {
		t.Fatal(err)
	}
	volume, err := fields.VolumeMeasurement.VolumeMeasurement()
	if err != nil || volume.UplinkVolume != 20 {
		t.Fatalf("retained usage %v: %v", volume, err)
	}
}
