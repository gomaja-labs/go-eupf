//go:build linux

package core

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/prometheus/client_golang/prometheus"
)

func bufferMetricValue(t *testing.T, name, reason string) (float64, bool) {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			matches := reason == ""
			for _, label := range metric.Label {
				if label.GetName() == "reason" && label.GetValue() == reason {
					matches = true
				}
			}
			if matches {
				if metric.Gauge != nil {
					return metric.Gauge.GetValue(), true
				}
				return metric.Counter.GetValue(), true
			}
		}
	}
	return 0, false
}

func TestPacketBufferMetricsCountOverflowExpiryAndCancellationOnce(t *testing.T) {
	plane, buffering, conn, _, session, peer := publishPacketBufferFixtureOptions(t, BufferingOptions{Packets: 2, PerSession: 2, FrameBytes: ebpf.BufferFrameSize, Retention: 500 * time.Millisecond})
	const counter = "upf_buffer_discarded_packets_total"
	const gauge = "upf_buffer_retained_packets"
	initial := map[string]float64{}
	for _, reason := range []string{"overflow", "expiry", "cancellation"} {
		initial[reason], _ = bufferMetricValue(t, counter, reason)
	}
	initialRetained, _ := bufferMetricValue(t, gauge, "")
	for _, id := range []uint16{100, 101, 102} {
		if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(reason string, want float64) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			got, found := bufferMetricValue(t, counter, reason)
			if found && got == initial[reason]+want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s=%g present=%t want=%g", reason, got, found, initial[reason]+want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// Check before expiry; the gauge includes ring records not yet copied to Go.
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		got, found := bufferMetricValue(t, gauge, "")
		if found && got == initialRetained+2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retained=%g present=%t want=%g", got, found, initialRetained+2)
		}
		time.Sleep(time.Millisecond)
	}
	wait("overflow", 1)
	buffering.mu.Lock()
	original := buffering.complete
	var retried atomic.Bool
	buffering.complete = func(command ebpf.BufferCommand) (ebpf.BufferCommand, error) {
		if !retried.Swap(true) {
			return ebpf.BufferCommand{}, errors.New("transient acknowledgement failure")
		}
		return original(command)
	}
	buffering.mu.Unlock()
	request := message.NewSessionModificationRequest(session.LocalSEID, 500, ie.NewPFCPSMReqFlags(1))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	if response, ok := identityRead(t, peer).(*message.SessionModificationResponse); !ok {
		t.Fatal("missing DROBU response")
	} else if cause, _ := response.Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatalf("DROBU cause=%d", cause)
	}
	wait("cancellation", 2)
	if !retried.Load() {
		t.Fatal("acknowledgement retry not exercised")
	}
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 103)); err != nil {
		t.Fatal(err)
	}
	wait("expiry", 1)
	deadline = time.Now().Add(time.Second)
	for {
		got, _ := bufferMetricValue(t, gauge, "")
		if got == initialRetained {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retained gauge leaked: %g", got)
		}
		time.Sleep(time.Millisecond)
	}
	wait("overflow", 1)
	wait("cancellation", 2)
}
