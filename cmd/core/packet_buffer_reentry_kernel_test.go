//go:build linux

package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// setBufferAction publishes a plain Update FAR that changes only Apply Action.
func setBufferAction(conn *PfcpConnection, assoc *NodeAssociation, before *Session, action uint8) (*Session, error) {
	after := cloneSession(before)
	far := after.FARs[1]
	far.FarInfo.Action = action
	after.FARs[1] = far
	start, finish := conn.prepareSessionMutation(after, updateSessionMutation)
	conn.stagePacketBuffering(assoc, before, after, updateSessionMutation, false)
	if err := start(); err != nil {
		_ = finish(false)
		return nil, err
	}
	if err := finish(true); err != nil {
		return nil, err
	}
	assoc.Sessions[after.LocalSEID] = after
	return after, nil
}

func firstBufferReport(t *testing.T, plane *ebpf.BpfObjects, conn *PfcpConnection, assoc *NodeAssociation, peer *net.UDPConn, id uint16) {
	t.Helper()
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		conn.serviceDownlinkNotifications(time.Now())
		conn.transport.mu.Lock()
		pending := len(conn.transport.pending)
		conn.transport.mu.Unlock()
		if pending != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("packet %d did not produce a Downlink Data Report", id)
		}
		time.Sleep(time.Millisecond)
	}
	report := identityRead(t, peer).(*message.SessionReportRequest)
	response := message.NewSessionReportResponse(11, report.Sequence(), ie.NewCause(ie.CauseRequestAccepted))
	conn.Handle(protocolWire(t, response), peer.LocalAddr().(*net.UDPAddr))
}

// Second buffering period while the first period's drain guard is still live.
func TestRebufferBeforeDrainRetirementNotifies(t *testing.T) {
	plane, _, conn, assoc, session, peer := publishPacketBufferFixture(t)
	firstBufferReport(t, plane, conn, assoc, peer, 100)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	forward := switchBufferedFARToForward(t, conn, assoc, session, hold)
	conn.stateMu.Lock()
	_, err := setBufferAction(conn, assoc, forward, 12)
	conn.stateMu.Unlock()
	if err != nil {
		t.Fatalf("BUFF|NOCP after FORW rejected: %v", err)
	}
	// A new BUFF|NOCP instruction starts a new buffering period: its first
	// downlink packet must be reported (TS 29.244 V20.1.0 clause 5.2.3.1).
	firstBufferReport(t, plane, conn, assoc, peer, 101)
}

// Control: the same sequence after the drain guard retired notifies again.
func TestRebufferAfterDrainRetirementNotifies(t *testing.T) {
	plane, buffering, conn, assoc, session, peer := publishPacketBufferFixture(t)
	packetBufferRoute(t, plane)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	buffering.sender = bufferSenderFunc(func(ebpf.RenderedBuffer) error { return nil })
	firstBufferReport(t, plane, conn, assoc, peer, 100)
	switchBufferedFARToForward(t, conn, assoc, session)
	deadline := time.Now().Add(2 * time.Second)
	for {
		buffering.mu.Lock()
		reserved := buffering.reserved
		buffering.mu.Unlock()
		if reserved == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("drain did not retire")
		}
		time.Sleep(time.Millisecond)
	}
	conn.stateMu.Lock()
	forward := assoc.Sessions[11]
	_, err := setBufferAction(conn, assoc, forward, 12)
	conn.stateMu.Unlock()
	if err != nil {
		t.Fatalf("BUFF|NOCP after FORW rejected: %v", err)
	}
	firstBufferReport(t, plane, conn, assoc, peer, 101)
}

func TestRepeatedBUFFNotifyInstructionStartsNewPeriod(t *testing.T) {
	plane, _, conn, assoc, session, peer := publishPacketBufferFixture(t)
	firstBufferReport(t, plane, conn, assoc, peer, 100)
	request := message.NewSessionModificationRequest(session.LocalSEID, 321,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(12)))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	response, ok := identityRead(t, peer).(*message.SessionModificationResponse)
	if !ok {
		t.Fatal("missing modification response")
	}
	cause, err := response.Cause.Cause()
	if err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("same-action instruction rejected: cause=%d error=%v", cause, err)
	}
	firstBufferReport(t, plane, conn, assoc, peer, 101)
}
