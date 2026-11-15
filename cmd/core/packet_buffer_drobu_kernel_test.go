//go:build linux

package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestModificationDROBUDropsRetainedPacketsAndRearmsNotification(t *testing.T) {
	plane, buffering, conn, assoc, before, peer := publishPacketBufferFixture(t)
	packetBufferRoute(t, plane)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	sent := make(chan uint16, 8)
	buffering.sender = bufferSenderFunc(func(packet ebpf.RenderedBuffer) error {
		sent <- binary.BigEndian.Uint16(packet.Frame[54:56])
		return nil
	})
	firstBufferReport(t, plane, conn, assoc, peer, 100)
	old := before.buffers.cycles[1]
	request := message.NewSessionModificationRequest(before.LocalSEID, 321, ie.NewPFCPSMReqFlags(1))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	response, ok := identityRead(t, peer).(*message.SessionModificationResponse)
	if !ok {
		t.Fatal("missing modification response")
	}
	cause, err := response.Cause.Cause()
	if err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("DROBU rejected: cause=%d %v", cause, err)
	}
	conn.stateMu.RLock()
	after := assoc.Sessions[before.LocalSEID]
	canceled, fresh := old.canceled, after.buffers.cycles[1].cookie != old.cookie
	conn.stateMu.RUnlock()
	if !canceled || !fresh {
		t.Fatal("DROBU retained the previous buffering period")
	}
	firstBufferReport(t, plane, conn, assoc, peer, 101)
	_ = switchBufferedFARToForward(t, conn, assoc, after)
	select {
	case id := <-sent:
		if id != 101 {
			t.Fatalf("pre-DROBU packet left after acceptance: %d", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new packet did not forward")
	}
	select {
	case id := <-sent:
		t.Fatalf("unexpected additional retained packet: %d", id)
	case <-time.After(100 * time.Millisecond):
	}
}
