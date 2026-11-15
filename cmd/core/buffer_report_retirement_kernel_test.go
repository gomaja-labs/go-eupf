//go:build linux

package core

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 clauses 7.5.9.1/.2: internal reclamation of a
// different FAR's drain cannot supersede controls sent by the CP.
func TestReportControlsSurviveAnotherFARDrainRetirement(t *testing.T) {
	plane, _, conn, assoc, _, peer := publishPacketBufferFixture(t)
	request := message.NewSessionModificationRequest(11, 100,
		ie.NewCreateBAR(ie.NewBARID(0)),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(12), ie.NewBARID(0)),
		ie.NewCreatePDR(ie.NewPDRID(10), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "198.51.100.3", "", 0, 0)), ie.NewFARID(2)))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	reply, ok := identityRead(t, peer).(*message.SessionModificationResponse)
	if !ok {
		t.Fatal("missing modification response")
	}
	if cause, _ := reply.Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatalf("second BUFF FAR cause=%d", cause)
	}
	conn.stateMu.RLock()
	before := assoc.Sessions[11]
	conn.stateMu.RUnlock()
	hold := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(hold) }) })
	forward := switchBufferedFARToForward(t, conn, assoc, before, hold)
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacketFor(t, 100, net.IP{198, 51, 100, 3})); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		conn.serviceDownlinkNotifications(time.Now())
		conn.transport.mu.Lock()
		pending := len(conn.transport.pending)
		conn.transport.mu.Unlock()
		if pending > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second FAR did not report")
		}
		time.Sleep(time.Millisecond)
	}
	report := identityRead(t, peer).(*message.SessionReportRequest)
	generation := forward.downlink.generation
	cookie := forward.buffers.cycles[2].cookie
	release.Do(func() { close(hold) })
	deadline = time.Now().Add(2 * time.Second)
	for {
		conn.stateMu.RLock()
		session := assoc.Sessions[11]
		retired := session.buffers.cycles[1] == nil
		conn.stateMu.RUnlock()
		if retired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first FAR drain did not retire")
		}
		time.Sleep(time.Millisecond)
	}
	response := message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted), ie.NewPFCPSRRspFlags(1),
		ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(0), ie.NewDLBufferingDuration(4*time.Second), ie.NewDLBufferingSuggestedPacketCount(3)))
	conn.Handle(protocolWire(t, response), peer.LocalAddr().(*net.UDPAddr))
	conn.stateMu.RLock()
	after := assoc.Sessions[11]
	applied := after.bar != nil && after.bar.duration == 4*time.Second && after.bar.dlPacketCount == 3 && after.downlink.generation == generation+1 && after.buffers.cycles[2].cookie != cookie
	conn.stateMu.RUnlock()
	if !applied {
		t.Fatal("internal drain retirement discarded DROBU or Update BAR")
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		outstanding, _, err := plane.BufferPoolUsage()
		if err != nil {
			t.Fatal(err)
		}
		if outstanding == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DROBU did not release retained credit")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUnrelatedModificationKeepsPendingReportControls(t *testing.T) {
	conn, _, session, peer := downlinkFixture(t, true)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
		t.Fatal(err)
	}
	queueDownlinkNotice(t, conn, session, 1, time.Now())
	report := identityRead(t, peer).(*message.SessionReportRequest)
	// Internal transaction generations are independent of CP buffering changes.
	session.buffers = &packetBufferSession{revision: 100}
	response := message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted), ie.NewPFCPSRRspFlags(1))
	// The model-only fixture does not have packet storage; validate just the gate.
	conn.stateMu.Lock()
	conn.transport.mu.Lock()
	pending := conn.transport.pending[report.Sequence()]
	conn.transport.mu.Unlock()
	err := conn.validateBufferReportResponseLocked(pending, response)
	applied := pending.bufferUpdate != nil
	conn.stateMu.Unlock()
	session.buffers = nil
	if err != nil || !applied {
		t.Fatalf("unrelated generation invalidated controls: %v", err)
	}
}

func TestBufferingRevisionIgnoresUsageAndInternalSlots(t *testing.T) {
	base := NewSession(11, 77, "", "", false)
	fid := uint32(1)
	base.FARs[1] = SFarInfo{GlobalId: 1, FarInfo: ebpf.FarInfo{Action: 12}}
	base.PDRs[1] = SPDRInfo{PdrID: 1, FARID: &fid, QERIDs: []uint32{1}, URRIDs: []uint32{1}}
	base.QERs[1] = SQerInfo{GlobalId: 1, QerInfo: ebpf.QerInfo{Qfi: 5, QFIPresent: true}}
	for _, tc := range []struct {
		name   string
		change func(*Session)
		want   bool
	}{
		{"usage binding", func(s *Session) {
			p := s.PDRs[1]
			p.URRIDs = []uint32{2}
			p.PdrInfo.UrrIDs = []uint32{200}
			s.PDRs[1] = p
		}, false},
		{"internal slots", func(s *Session) {
			f := s.FARs[1]
			f.GlobalId = 99
			f.FarInfo.BufferCookie = 999
			s.FARs[1] = f
			p := s.PDRs[1]
			p.PdrInfo.FarId = 99
			p.PdrInfo.QerIDs = []uint32{100}
			s.PDRs[1] = p
			q := s.QERs[1]
			q.GlobalId = 100
			q.QerInfo.PolicerID = 50
			s.QERs[1] = q
		}, false},
		{"FAR action", func(s *Session) { f := s.FARs[1]; f.FarInfo.Action = 2; s.FARs[1] = f }, true},
		{"PDR flow", func(s *Session) { p := s.PDRs[1]; p.PdrInfo.QFIs = []uint8{9}; s.PDRs[1] = p }, true},
		{"QER QFI", func(s *Session) { q := s.QERs[1]; q.QerInfo.Qfi = 9; s.QERs[1] = q }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := cloneSession(base)
			tc.change(next)
			if got := bufferingModificationChanged(base, next, false, nil); got != tc.want {
				t.Fatalf("changed=%t want=%t", got, tc.want)
			}
		})
	}
	if !bufferingModificationChanged(base, cloneSession(base), false, []uint32{1}) {
		t.Fatal("repeated BUFF|NOCP did not start a new control revision")
	}
}
