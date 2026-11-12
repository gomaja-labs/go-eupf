package core

import (
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/prometheus/client_golang/prometheus"
)

// durationSample returns the sample count and sum of the processing-duration
// summary for one message type.
func durationSample(t *testing.T, registry *prometheus.Registry, messageType string) (uint64, float64) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "upf_pfcp_rx_duration_seconds" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "message_type" && label.GetValue() == messageType {
					return metric.GetSummary().GetSampleCount(), metric.GetSummary().GetSampleSum()
				}
			}
		}
	}
	return 0, 0
}

func TestPFCPProcessingDurationIsObservedInSeconds(t *testing.T) {
	conn := newProtocolConnection(t)
	registry := prometheus.NewRegistry()
	registry.MustRegister(UpfMessageRxLatency)
	request := message.NewHeartbeatRequest(1, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))
	count, sum := durationSample(t, registry, request.MessageTypeName())
	if reply := exchangeProtocolDatagram(t, conn, protocolWire(t, request)); reply == nil {
		t.Fatal("no Heartbeat Response")
	}
	newCount, newSum := durationSample(t, registry, request.MessageTypeName())
	if newCount != count+1 {
		t.Fatalf("observations = %d, want %d", newCount, count+1)
	}
	// Handling one loopback heartbeat takes far less than a second, so an
	// observation of one or more means the duration was not recorded in seconds.
	if d := newSum - sum; d <= 0 || d >= 1 {
		t.Fatalf("observed duration %v, want seconds in (0, 1)", d)
	}
}
