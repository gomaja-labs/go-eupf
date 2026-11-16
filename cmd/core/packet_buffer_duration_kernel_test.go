//go:build linux

package core

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestApplicationBufferGraceWaitPreservesTheDrainWindow(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixtureOptions(t, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: 50 * time.Millisecond})
	packetBufferRoute(t, plane)
	session = installPacketBufferDuration(t, conn, assoc, session)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan uint16, 4)
	buffering.sender = bufferSenderFunc(func(packet ebpf.RenderedBuffer) error {
		delivered <- binary.BigEndian.Uint16(packet.Frame[54:56])
		return nil
	})
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	additional := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(additional) }) })
	session = switchBufferedFARToForward(t, conn, assoc, session, additional)
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 101)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		conn.stateMu.RLock()
		received := session.buffers.cycles[1].received
		conn.stateMu.RUnlock()
		if received == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reader did not consume both sides of the forwarding transition")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	buffering.mu.Lock()
	held := len(buffering.entries) - len(buffering.free)
	buffering.mu.Unlock()
	if held != 2 || len(delivered) != 0 {
		t.Fatalf("grace wait consumed the drain window: held=%d sent=%d", held, len(delivered))
	}
	release.Do(func() { close(additional) })
	for _, want := range []uint16{100, 101} {
		select {
		case got := <-delivered:
			if got != want {
				t.Fatalf("drain order=%d want=%d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("packet lost its output window while waiting for grace")
		}
	}
}

func installPacketBufferDuration(t *testing.T, conn *PfcpConnection, assoc *NodeAssociation, before *Session) *Session {
	t.Helper()
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	after := cloneSession(before)
	if err := createBAR(after, ie.NewCreateBAR(ie.NewBARID(0), ie.NewDLBufferingDuration(2*time.Second), ie.NewDLBufferingSuggestedPacketCount(1))); err != nil {
		t.Fatal(err)
	}
	barID := uint8(0)
	far := after.FARs[1]
	far.BARID = &barID
	after.FARs[1] = far
	start, finish := conn.prepareSessionMutation(after, updateSessionMutation, true)
	defer func() {
		if err := finish(false); err != nil {
			t.Error(err)
		}
	}()
	conn.stagePacketBuffering(assoc, before, after, updateSessionMutation, false)
	if err := start(); err != nil {
		t.Fatal(err)
	}
	if err := finish(true); err != nil {
		t.Fatal(err)
	}
	assoc.Sessions[11] = after
	return after
}

func TestPacketBufferDurationRetainsThenExpiresActualPackets(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixtureOptions(t, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: 50 * time.Millisecond})
	session = installPacketBufferDuration(t, conn, assoc, session)
	go conn.Run()
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	buffering.mu.Lock()
	held := len(buffering.entries) - len(buffering.free)
	buffering.mu.Unlock()
	if held != 1 {
		t.Fatal("extended duration was replaced by the ordinary retention limit")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		buffering.mu.Lock()
		held = len(buffering.entries) - len(buffering.free)
		buffering.mu.Unlock()
		if held == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired extended packet remained buffered")
		}
		time.Sleep(time.Millisecond)
	}
	conn.stateMu.RLock()
	duration, count := session.bar.durationPresent, session.bar.dlPacketCountPresent
	conn.stateMu.RUnlock()
	if duration || count {
		t.Fatal("expired extended parameters remained in the BAR")
	}
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 101)); err != nil {
		t.Fatal(err)
	}
	cycle := session.buffers.cycles[1]
	state, err := plane.BufferControl(ebpf.BufferCommand{SessionID: 11, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 3})
	if err != nil || state.Produced != 2 || state.BARDLLimit != 4 {
		t.Fatalf("expired DL limit remained active: %+v %v", state, err)
	}
}

func TestApplicationBufferExtendedPacketDrainsBeforeExpiry(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixtureOptions(t, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: 200 * time.Millisecond})
	packetBufferRoute(t, plane)
	session = installPacketBufferDuration(t, conn, assoc, session)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan struct{}, 1)
	buffering.sender = bufferSenderFunc(func(ebpf.RenderedBuffer) error { delivered <- struct{}{}; return nil })
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	session = switchBufferedFARToForward(t, conn, assoc, session)
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("forwarding discarded a packet retained by extended buffering")
	}
	conn.stateMu.RLock()
	duration, count := session.bar.durationPresent, session.bar.dlPacketCountPresent
	conn.stateMu.RUnlock()
	if duration || count {
		t.Fatal("ending buffering retained the extended-only BAR parameters")
	}
}
