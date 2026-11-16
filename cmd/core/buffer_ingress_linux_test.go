//go:build linux

package core

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"golang.org/x/sys/unix"
)

func TestKernelContinuationRemovedIngressIsTerminal(t *testing.T) {
	sender := &bufferPacketSender{fd: -1}
	err := sender.Send(ebpf.RenderedBuffer{Frame: make([]byte, 60), Action: 2, IngressIfindex: 0x7ffffff0})
	if !errors.Is(err, unix.ENODEV) {
		t.Fatalf("removed ingress must preserve ENODEV: %v", err)
	}
}

func TestBufferedRemovedIngressDiscardsOnceWithoutFailure(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixture(t)
	packetBufferRoute(t, plane)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	sender := &bufferPacketSender{fd: -1}
	var sends atomic.Int32
	buffering.sender = bufferSenderFunc(func(packet ebpf.RenderedBuffer) error {
		sends.Add(1)
		packet.Action = 2
		packet.IngressIfindex = 0x7ffffff0
		return sender.Send(packet)
	})
	before := counterValue(t, bufferDiscardedPackets.WithLabelValues("ingress_removed"))
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	switchBufferedFARToForward(t, conn, assoc, session)
	deadline := time.Now().Add(time.Second)
	for counterValue(t, bufferDiscardedPackets.WithLabelValues("ingress_removed")) == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := counterValue(t, bufferDiscardedPackets.WithLabelValues("ingress_removed")) - before; got != 1 {
		t.Fatalf("ingress_removed=%g want 1", got)
	}
	time.Sleep(40 * time.Millisecond)
	if sends.Load() != 1 {
		t.Fatalf("terminal discard retried %d times", sends.Load())
	}
	select {
	case err := <-buffering.Failures():
		t.Fatalf("packet discard failed process: %v", err)
	default:
	}
}
