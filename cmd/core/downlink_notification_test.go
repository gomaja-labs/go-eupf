package core

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func downlinkFixture(t *testing.T, is5G bool) (*PfcpConnection, *NodeAssociation, *Session, *net.UDPConn) {
	t.Helper()
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.92", 8805)
	assoc := NewNodeAssociation("notify.example", "127.0.0.93")
	session := NewSession(11, 77, "", "", false)
	session.Is5G = is5G
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.92")
	session.downlink = newDownlinkNotifications(8)
	barID := uint8(0)
	session.FARs[1] = SFarInfo{BARID: &barID, FarInfo: ebpf.FarInfo{Action: 12, BufferSessionID: 11, BufferCookie: 7}}
	session.FARs[2] = SFarInfo{BARID: &barID, FarInfo: ebpf.FarInfo{Action: 12, BufferSessionID: 11, BufferCookie: 8, BufferLane: 1}}
	assoc.Sessions[11] = session
	conn.NodeAssociations[assoc.ID] = assoc
	conn.downlinkSessions = map[uint64]*NodeAssociation{11: assoc}
	return conn, assoc, session, peer
}

func TestDownlinkNotificationCoalescesPerFAROrFlow(t *testing.T) {
	for _, is5G := range []bool{false, true} {
		name := "EPC"
		if is5G {
			name = "5GC"
		}
		t.Run(name, func(t *testing.T) {
			conn, _, session, peer := downlinkFixture(t, is5G)
			if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.NewDownlinkDataNotificationDelay(150*time.Millisecond))); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			conn.stateMu.Lock()
			for _, packet := range []struct {
				far     uint32
				pdr     uint32
				qfi     uint8
				present bool
				cookie  uint64
			}{
				{1, 1, 0, true, 7}, {1, 99, 0, true, 7}, {1, 3, 9, true, 7}, {1, 4, 0, false, 7}, {2, 2, 9, true, 8},
			} {
				conn.noteDownlinkPacketLocked(session, packet.far, ebpf.BufferRecord{SessionID: 11, Cookie: packet.cookie, PDRID: packet.pdr, QFI: packet.qfi, QFIPresent: packet.present, Notify: true}, now)
			}
			conn.stateMu.Unlock()
			if !is5G {
				conn.serviceDownlinkNotifications(now.Add(149 * time.Millisecond))
				if len(conn.transport.pending) != 0 {
					t.Fatal("notification ignored its BAR delay")
				}
			}
			conn.serviceDownlinkNotifications(now.Add(150 * time.Millisecond))
			want := 2
			if is5G {
				want = 4
			}
			if len(conn.transport.pending) != want {
				t.Fatalf("coalesced reports=%d want=%d", len(conn.transport.pending), want)
			}
			seen := make(map[[2]uint16]bool)
			for range want {
				report, ok := identityRead(t, peer).(*message.SessionReportRequest)
				if !ok || report.SEID() != 77 || !report.ReportType.HasDLDR() {
					t.Fatalf("not a DLDR for CP F-SEID: %T", report)
				}
				fields, err := report.DownlinkDataReport.DownlinkDataReport()
				if err != nil || len(fields.PDRID) != 1 {
					t.Fatalf("Downlink Data Report fields=%+v error=%v", fields, err)
				}
				pdr, err := fields.PDRID[0].PDRID()
				if err != nil {
					t.Fatal(err)
				}
				flow := uint16(64)
				if len(fields.DownlinkDataServiceInformation) > 0 {
					service, err := fields.DownlinkDataServiceInformation[0].DownlinkDataServiceInformation()
					if err != nil || service.Flags&1 != 0 {
						t.Fatalf("unexpected paging-policy support: %+v %v", service, err)
					}
					flow = uint16(service.QFI)
				}
				if !is5G && (pdr != 1 && pdr != 2 || flow != 64) {
					t.Fatalf("EPC did not retain its first packet: PDR=%d flow=%d", pdr, flow)
				}
				key := [2]uint16{pdr, flow}
				if seen[key] {
					t.Fatalf("duplicate report: %+v", key)
				}
				seen[key] = true
			}
			if is5G {
				for _, key := range [][2]uint16{{1, 0}, {3, 9}, {4, 64}, {2, 9}} {
					if !seen[key] {
						t.Fatalf("missing report for PDR/flow %+v", key)
					}
				}
			}
		})
	}
}

func queueDownlinkNotice(t *testing.T, conn *PfcpConnection, session *Session, pdr uint32, now time.Time) {
	t.Helper()
	conn.stateMu.Lock()
	conn.noteDownlinkPacketLocked(session, 1, ebpf.BufferRecord{SessionID: 11, Cookie: 7, PDRID: pdr, QFI: 0, QFIPresent: true, Notify: true}, now)
	conn.stateMu.Unlock()
	conn.serviceDownlinkNotifications(now)
}

func TestDownlinkNotificationTerminalOutcomesRearmOnlyNewPackets(t *testing.T) {
	for _, outcome := range []string{"accepted", "rejected", "invalid_length", "missing_cause", "wrong_seid", "timeout"} {
		t.Run(outcome, func(t *testing.T) {
			conn, _, session, peer := downlinkFixture(t, true)
			conn.requestTimeout = time.Millisecond
			conn.requestRetries = 1
			now := time.Now()
			queueDownlinkNotice(t, conn, session, 1, now)
			first := identityRead(t, peer).(*message.SessionReportRequest)
			response := message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseRequestAccepted))
			switch outcome {
			case "rejected":
				response.Cause = ie.NewCause(ie.CauseNoResourcesAvailable)
			case "missing_cause":
				response.Cause = nil
			case "wrong_seid":
				response.Header.SEID = 12
			}
			if outcome == "timeout" {
				conn.serviceTransactions(now.Add(time.Second))
				retry := identityRead(t, peer).(*message.SessionReportRequest)
				if retry.Sequence() != first.Sequence() {
					t.Fatal("retransmission changed its sequence")
				}
				conn.serviceTransactions(now.Add(2 * time.Second))
			} else {
				wire := protocolWire(t, response)
				if outcome == "invalid_length" {
					binary.BigEndian.PutUint16(wire[2:4], uint16(len(wire)-3))
				}
				conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
			}
			if len(conn.transport.pending) != 0 {
				t.Fatal("terminal result retained a pending request")
			}
			conn.serviceDownlinkNotifications(now.Add(3 * time.Second))
			if len(conn.transport.pending) != 0 {
				t.Fatal("failed report restarted without a new packet")
			}
			queueDownlinkNotice(t, conn, session, 8, now.Add(4*time.Second))
			if outcome == "accepted" {
				if len(conn.transport.pending) != 0 {
					t.Fatal("accepted flow reported twice in one buffering lifetime")
				}
			} else {
				if len(conn.transport.pending) != 1 {
					t.Fatal("failed flow was not rearmed for its next packet")
				}
				next := identityRead(t, peer).(*message.SessionReportRequest)
				fields, err := next.DownlinkDataReport.DownlinkDataReport()
				if err != nil {
					t.Fatal(err)
				}
				pdr, _ := fields.PDRID[0].PDRID()
				if next.Sequence() == first.Sequence() || pdr != 8 {
					t.Fatalf("rearmed report sequence=%d PDR=%d", next.Sequence(), pdr)
				}
			}
		})
	}
}

func TestDownlinkNotificationCannotChangeReplacementLifetime(t *testing.T) {
	conn, assoc, session, peer := downlinkFixture(t, true)
	now := time.Now()
	queueDownlinkNotice(t, conn, session, 1, now)
	first := identityRead(t, peer).(*message.SessionReportRequest)
	replacement := *session
	replacement.downlink = newDownlinkNotifications(8)
	replacement.FARs = map[uint32]SFarInfo{1: {FarInfo: ebpf.FarInfo{Action: 12, BufferSessionID: 11, BufferCookie: 7}}}
	assoc.Sessions[11] = &replacement
	queueDownlinkNotice(t, conn, &replacement, 2, now)
	second := identityRead(t, peer).(*message.SessionReportRequest)
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseSystemFailure))), peer.LocalAddr().(*net.UDPAddr))
	queueDownlinkNotice(t, conn, &replacement, 3, now)
	if len(conn.transport.pending) != 1 || conn.transport.pending[second.Sequence()] == nil {
		t.Fatal("old completion rearmed the replacement lifetime")
	}
}

func TestDownlinkExtendedBufferingSuppressesUntilOriginalExpiry(t *testing.T) {
	conn, _, session, peer := downlinkFixture(t, true)
	now := time.Now()
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.NewDLBufferingDuration(2*time.Second), ie.NewDLBufferingSuggestedPacketCount(8))); err != nil {
		t.Fatal(err)
	}
	queueDownlinkNotice(t, conn, session, 1, now)
	if len(conn.transport.pending) != 0 {
		t.Fatal("extended buffering did not suppress notification")
	}
	if err := updateBAR(session, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(4))); err != nil {
		t.Fatal(err)
	}
	conn.serviceDownlinkNotifications(now.Add(time.Second))
	if !session.downlink.extendedUntil.Equal(now.Add(2 * time.Second)) {
		t.Fatal("unrelated BAR update restarted extended buffering")
	}
	conn.serviceDownlinkNotifications(now.Add(2 * time.Second))
	if session.bar.durationPresent || session.bar.dlPacketCountPresent {
		t.Fatal("expired extended parameters remained provisioned")
	}
	queueDownlinkNotice(t, conn, session, 2, now.Add(2*time.Second))
	if len(conn.transport.pending) != 1 {
		t.Fatal("notification was not rearmed after extended buffering")
	}
	_ = identityRead(t, peer)
}

func TestDownlinkInfiniteBufferingCanBeStoppedOrRemoved(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(strconv.FormatBool(remove), func(t *testing.T) {
			conn, _, session, peer := downlinkFixture(t, true)
			now := time.Now()
			if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.New(ie.DLBufferingDuration, []byte{0xe0}), ie.NewDLBufferingSuggestedPacketCount(8))); err != nil {
				t.Fatal(err)
			}
			queueDownlinkNotice(t, conn, session, 1, now)
			conn.serviceDownlinkNotifications(now.Add(24 * time.Hour))
			if len(conn.transport.pending) != 0 {
				t.Fatal("infinite buffering expired")
			}
			if remove {
				if err := removeBAR(session, ie.NewRemoveBAR(ie.NewBARID(0))); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := updateBAR(session, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0), ie.New(ie.DLBufferingDuration, []byte{0}))); err != nil {
					t.Fatal(err)
				}
			}
			// The publication callback applies changed BAR controls before maintenance.
			conn.stateMu.Lock()
			conn.applyDownlinkDurationLocked(session, now.Add(24*time.Hour))
			conn.stateMu.Unlock()
			conn.serviceDownlinkNotifications(now.Add(24 * time.Hour))
			if session.bar != nil && (session.bar.durationPresent || session.bar.dlPacketCountPresent) {
				t.Fatal("stopped extended parameters remained provisioned")
			}
			queueDownlinkNotice(t, conn, session, 2, now.Add(24*time.Hour))
			if len(conn.transport.pending) != 1 {
				t.Fatal("stopping/removing extended buffering did not rearm")
			}
			_ = identityRead(t, peer)
		})
	}
}

func TestDownlinkReportResponseAppliesBARAndDropControls(t *testing.T) {
	for _, kind := range []string{"update", "drop", "both", "spare_flags"} {
		t.Run(kind, func(t *testing.T) {
			conn, _, session, peer := downlinkFixture(t, true)
			if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(8))); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			queueDownlinkNotice(t, conn, session, 1, now)
			first := identityRead(t, peer).(*message.SessionReportRequest)
			response := message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseRequestAccepted))
			if kind == "update" || kind == "both" {
				response.UpdateBAR = ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(0), ie.NewDLBufferingDuration(4*time.Second), ie.NewDLBufferingSuggestedPacketCount(3))
			}
			if kind == "drop" || kind == "both" {
				response.PFCPSRRspFlags = ie.NewPFCPSRRspFlags(1)
			}
			if kind == "spare_flags" {
				response.PFCPSRRspFlags = ie.NewPFCPSRRspFlags(0xfe)
			}
			conn.Handle(protocolWire(t, response), peer.LocalAddr().(*net.UDPAddr))
			if kind == "update" || kind == "both" {
				if !session.bar.durationPresent || session.bar.duration != 4*time.Second || session.bar.dlPacketCount != 3 || session.barRevision != 2 {
					t.Fatalf("Report Response BAR was not applied: %+v revision=%d", session.bar, session.barRevision)
				}
				queueDownlinkNotice(t, conn, session, 2, now)
				if len(conn.transport.pending) != 0 {
					t.Fatal("response extended buffering did not suppress notifications")
				}
			}
			if kind == "drop" || kind == "both" {
				if session.downlink.generation != 2 {
					t.Fatal("DROBU did not cancel the notification generation")
				}
			} else if session.downlink.generation != 1 {
				t.Fatal("spare response flags changed buffering state")
			}
			if kind == "drop" {
				queueDownlinkNotice(t, conn, session, 2, now)
				if len(conn.transport.pending) != 1 {
					t.Fatal("DROBU did not rearm a new first packet")
				}
				_ = identityRead(t, peer)
			}
		})
	}
}

func TestDownlinkReportResponseRejectsInvalidBARAtomically(t *testing.T) {
	for _, update := range []*ie.IE{
		ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(1)),
		ie.NewUpdateBARWithinSessionReportResponse(),
		ie.New(ie.UpdateBARWithinSessionReportResponse, []byte{0, 88, 0, 2, 1}),
		ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(0), ie.New(ie.ExtendedDLBufferingNotificationPolicy, []byte{1})),
	} {
		conn, _, session, peer := downlinkFixture(t, true)
		if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
			t.Fatal(err)
		}
		before := session.bar
		now := time.Now()
		queueDownlinkNotice(t, conn, session, 1, now)
		first := identityRead(t, peer).(*message.SessionReportRequest)
		response := message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseRequestAccepted), update, ie.NewPFCPSRRspFlags(1))
		conn.Handle(protocolWire(t, response), peer.LocalAddr().(*net.UDPAddr))
		if session.bar != before || session.downlink.generation != 1 || len(conn.transport.pending) != 0 {
			t.Fatal("invalid Update BAR applied partial controls")
		}
		queueDownlinkNotice(t, conn, session, 2, now)
		if len(conn.transport.pending) != 1 {
			t.Fatal("invalid BAR response did not rearm its failed notification")
		}
		_ = identityRead(t, peer)
		conn.Close()
		if err := peer.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDownlinkReportResponseCannotUndoLaterBAROrLifetime(t *testing.T) {
	for _, later := range []string{"bar", "generation", "replacement"} {
		t.Run(later, func(t *testing.T) {
			conn, assoc, session, peer := downlinkFixture(t, true)
			if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			queueDownlinkNotice(t, conn, session, 1, now)
			first := identityRead(t, peer).(*message.SessionReportRequest)
			switch later {
			case "bar":
				session.bufferControlRevision++ // accepted CP Session Modification
				if err := updateBAR(session, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(2))); err != nil {
					t.Fatal(err)
				}
			case "generation":
				session.bufferControlRevision++ // accepted CP DROBU modification
				session.downlink.generation++
			case "replacement":
				replacement := *session
				replacement.downlink = newDownlinkNotifications(8)
				session = &replacement
				assoc.Sessions[11] = session
			}
			bar, generation := session.bar, session.downlink.generation
			response := message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseRequestAccepted), ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(0), ie.NewDLBufferingDuration(4*time.Second)), ie.NewPFCPSRRspFlags(1))
			conn.Handle(protocolWire(t, response), peer.LocalAddr().(*net.UDPAddr))
			if session.bar != bar || session.downlink.generation != generation {
				t.Fatal("late Report Response changed newer buffering state")
			}
		})
	}
}

func TestDownlinkReportCompletionReoriginatesAtCurrentCPFSEID(t *testing.T) {
	conn, _, session, oldPeer := downlinkFixture(t, true)
	newPeer := identityPeer(t, "127.0.0.91", 8805)
	now := time.Now()
	queueDownlinkNotice(t, conn, session, 1, now)
	first := identityRead(t, oldPeer).(*message.SessionReportRequest)
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.91")
	session.RemoteSEID = 88
	response := message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseRequestAccepted), ie.NewPFCPSRRspFlags(1))
	conn.Handle(protocolWire(t, response), oldPeer.LocalAddr().(*net.UDPAddr))
	next := identityRead(t, newPeer).(*message.SessionReportRequest)
	if next.Sequence() == first.Sequence() || next.SEID() != 88 || session.downlink.generation != 1 {
		t.Fatal("old CP response changed buffering or reused its procedure")
	}
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, next.Sequence(), ie.NewCause(ie.CauseRequestAccepted))), newPeer.LocalAddr().(*net.UDPAddr))
	if len(conn.transport.pending) != 0 {
		t.Fatal("current CP report did not finish")
	}
}

func TestDownlinkCompletionCannotRearmAfterExtendedBufferingEnds(t *testing.T) {
	conn, _, session, peer := downlinkFixture(t, true)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	queueDownlinkNotice(t, conn, session, 1, now)
	old := identityRead(t, peer).(*message.SessionReportRequest)
	if err := updateBAR(session, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0), ie.NewDLBufferingDuration(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	// Match packetBufferPlan.finish: publication starts the new duration.
	conn.stateMu.Lock()
	conn.applyDownlinkDurationLocked(session, now)
	conn.stateMu.Unlock()
	conn.serviceDownlinkNotifications(now)
	conn.serviceDownlinkNotifications(now.Add(2 * time.Second))
	queueDownlinkNotice(t, conn, session, 2, now.Add(2*time.Second))
	current := identityRead(t, peer).(*message.SessionReportRequest)
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, old.Sequence(), ie.NewCause(ie.CauseSystemFailure))), peer.LocalAddr().(*net.UDPAddr))
	queueDownlinkNotice(t, conn, session, 3, now.Add(3*time.Second))
	if len(conn.transport.pending) != 1 || conn.transport.pending[current.Sequence()] == nil {
		t.Fatal("old completion rearmed a flow after extended-buffering expiry")
	}
}

func TestStaleDownlinkCompletionCannotReoriginateRemovedFAR(t *testing.T) {
	conn, _, session, peer := downlinkFixture(t, true)
	now := time.Now()
	queueDownlinkNotice(t, conn, session, 1, now)
	old := identityRead(t, peer).(*message.SessionReportRequest)
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.91")
	far := session.FARs[1]
	far.FarInfo.BufferCookie = 8
	session.FARs[1] = far
	conn.Handle(protocolWire(t, message.NewSessionReportResponse(11, old.Sequence(), ie.NewCause(ie.CauseSystemFailure))), peer.LocalAddr().(*net.UDPAddr))
	if len(conn.transport.pending) != 0 {
		t.Fatal("stale FAR report was reoriginated at a new CP")
	}
}

func TestReportControlsRemainValidAfterAnotherReportResponse(t *testing.T) {
	for _, firstDrop := range []bool{false, true} {
		t.Run(strconv.FormatBool(firstDrop), func(t *testing.T) {
			conn, _, session, peer := downlinkFixture(t, true)
			if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			queueDownlinkNotice(t, conn, session, 1, now)
			first := identityRead(t, peer).(*message.SessionReportRequest)
			conn.stateMu.Lock()
			conn.noteDownlinkPacketLocked(session, 2, ebpf.BufferRecord{SessionID: 11, Cookie: 8, PDRID: 2, QFI: 9, QFIPresent: true, Notify: true}, now)
			conn.stateMu.Unlock()
			conn.serviceDownlinkNotifications(now)
			second := identityRead(t, peer).(*message.SessionReportRequest)
			controls := func(report *message.SessionReportRequest, drop bool) *message.SessionReportResponse {
				response := message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))
				if drop {
					response.PFCPSRRspFlags = ie.NewPFCPSRRspFlags(1)
				} else {
					response.UpdateBAR = ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(0), ie.NewDLBufferingSuggestedPacketCount(3))
				}
				return response
			}
			conn.Handle(protocolWire(t, controls(first, firstDrop)), peer.LocalAddr().(*net.UDPAddr))
			conn.Handle(protocolWire(t, controls(second, !firstDrop)), peer.LocalAddr().(*net.UDPAddr))
			if session.downlink.generation != 2 || !session.bar.dlPacketCountPresent || session.bar.dlPacketCount != 3 {
				t.Fatalf("second report's controls were discarded: generation=%d BAR=%+v", session.downlink.generation, session.bar)
			}
		})
	}
}
