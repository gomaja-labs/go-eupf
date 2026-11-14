//go:build linux

package core

import (
	"errors"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

func TestPacketBufferingDefersOutputUntilBUFF(t *testing.T) {
	_, buffering, conn, assoc, session, _ := packetBufferFixture(t)
	sender := buffering.sender.(*bufferPacketSender)
	if sender.fd >= 0 || sender.kernel != nil {
		t.Fatal("readiness created buffered output before any BUFF admission")
	}
	conn.stateMu.Lock()
	_, err := conn.reservePacketBuffers(assoc, session)
	conn.stateMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if sender.fd < 0 || sender.kernel == nil {
		t.Fatal("BUFF admitted before preparing its forwarding continuations")
	}
}

func TestPacketBufferInitializationFailureRejectsBUFFBeforePublication(t *testing.T) {
	if err := ebpf.IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	plane := ebpf.NewBpfObjects()
	if err := plane.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := plane.Close(); err != nil {
			t.Error(err)
		}
	})
	// Keep the ring/maps live but make the private loader's source unavailable.
	if err := plane.UpfIpEntrypointFunc.Close(); err != nil {
		t.Fatal(err)
	}
	buffering, err := NewPacketBuffering(plane, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
	if err != nil {
		t.Fatalf("unused private output blocked readiness: %v", err)
	}
	t.Cleanup(func() {
		if err := buffering.Close(); err != nil {
			t.Error(err)
		}
	})
	conn, assoc, session, _ := downlinkFixture(t, true)
	conn.mapOperations = plane
	t.Cleanup(func() {
		conn.stateMu.Lock()
		clear(session.FARs)
		conn.stateMu.Unlock()
	})
	if err := conn.SetPacketBuffering(buffering); err != nil {
		t.Fatal(err)
	}
	conn.stateMu.Lock()
	_, err = conn.reservePacketBuffers(assoc, session)
	conn.stateMu.Unlock()
	if err == nil {
		t.Fatal("BUFF admitted despite private program initialization failure")
	}
	var invalid *requestIEError
	if !errors.As(err, &invalid) || invalid.cause != ie.CauseSystemFailure {
		t.Fatalf("load failure did not return Cause 77: %v", err)
	}
	if session.buffers != nil || len(buffering.owners) != 0 {
		t.Fatal("failed output initialization published buffering state")
	}
	outstanding, dropped, usageErr := plane.BufferPoolUsage()
	if usageErr != nil || outstanding != 0 || dropped != 0 {
		t.Fatalf("failed initialization retained packets: %d %d %v", outstanding, dropped, usageErr)
	}
	// A BAR-only session remains admissible, and a later first BUFF must fail
	// before creating a cycle on that already admitted metadata owner.
	for id, far := range session.FARs {
		far.FarInfo.Action = 2
		session.FARs[id] = far
	}
	session.bar = &bufferingActionRule{id: 0}
	conn.stateMu.Lock()
	owner, barErr := conn.reservePacketBuffers(assoc, session)
	conn.stateMu.Unlock()
	if barErr != nil || owner == nil {
		t.Fatalf("BAR-only admission required private output: %v", barErr)
	}
	conn.stateMu.Lock()
	_, cycleErr := buffering.reserveCycle(owner, 1)
	conn.stateMu.Unlock()
	if cycleErr == nil || len(owner.cycles) != 0 {
		t.Fatalf("first BUFF on BAR owner bypassed initialization: %v", cycleErr)
	}
}
