//go:build linux

package core

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestPacketBufferBackgroundPreparationAnswersHeartbeat(t *testing.T) {
	plane, buffering, conn, _, _, peer := packetBufferFixtureStartOptions(t, false, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
	starter, ok := any(buffering).(interface {
		Start(context.Context) <-chan struct{}
	})
	if !ok {
		t.Fatal("buffer output has no background preparation; first BUFF loads on the PFCP loop")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := time.Now()
	done := starter.Start(ctx)
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("starting background preparation blocked")
	}
	go conn.Run()
	heartbeat := message.NewHeartbeatRequest(123, ie.NewRecoveryTimeStamp(time.Unix(1800000000, 0)), nil)
	sent := time.Now()
	if _, err := peer.WriteToUDP(protocolWire(t, heartbeat), conn.socket().LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if _, ok := identityRead(t, peer).(*message.HeartbeatResponse); !ok {
		t.Fatal("heartbeat was not answered during initialization")
	}
	if delay := time.Since(sent); delay > 250*time.Millisecond {
		t.Fatalf("heartbeat waited for background verification: %s", delay)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("background preparation did not finish")
	}
	if plane.UpfBufferAdmissionFunc == nil {
		t.Fatal("background preparation never installed admission")
	}
}

func TestPacketBufferCancellationInterruptsAdmission(t *testing.T) {
	_, buffering, _, _, _, _ := packetBufferFixtureStartOptions(t, false, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
	completed := make(chan error, 1)
	go func() { completed <- buffering.prepareOutput(11) }()
	buffering.CancelPreparation()
	select {
	case err := <-completed:
		if err == nil {
			t.Fatal("canceled preparation admitted BUFF")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("shutdown waited for verification")
	}
}

func TestPacketBufferPreparedAdmissionDoesNotVerify(t *testing.T) {
	_, buffering, _, _, _, _ := packetBufferFixtureStartOptions(t, false, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Exact readiness-to-admission timing belongs to the isolated chart
	// capture. This correctness test does not assume an idle verifier host.
	select {
	case <-buffering.Start(ctx):
	case <-time.After(30 * time.Second):
		t.Fatal("background preparation did not finish before admission")
	}
	started := time.Now()
	if err := buffering.prepareOutput(11); err != nil {
		t.Fatal(err)
	}
	if delay := time.Since(started); delay > 250*time.Millisecond {
		t.Fatalf("prepared BUFF admission performed more initialization: %s", delay)
	}
}

func TestPacketBufferCancellationPreventsLateInstallation(t *testing.T) {
	for _, beforeStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "during-load", true: "before-start"}[beforeStart], func(t *testing.T) {
			plane, buffering, _, _, _, _ := packetBufferFixtureStartOptions(t, false, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
			before := plane.UpfIpEntrypointFunc
			if beforeStart {
				buffering.CancelPreparation()
			}
			done := buffering.Start(context.Background())
			started := time.Now()
			buffering.CancelPreparation()
			if time.Since(started) > 250*time.Millisecond {
				t.Fatal("shutdown cancellation waited for verification")
			}
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("canceled output preparation did not finish")
			}
			program, err := plane.BufferKernelIngressProgram()
			if program != nil {
				_ = program.Close()
			}
			if err == nil {
				t.Fatal("shutdown cancellation left prepared output")
			}
			if plane.UpfIpEntrypointFunc != before || plane.UpfBufferAdmissionFunc != nil {
				t.Fatal("shutdown cancellation installed live forwarding")
			}
		})
	}
}
