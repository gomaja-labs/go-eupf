package core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	bufferRetainedPackets  = promauto.NewGauge(prometheus.GaugeOpts{Name: "upf_buffer_retained_packets", Help: "Packets retained in the admission ring or application storage until acknowledgement"})
	bufferDiscardedPackets = promauto.NewCounterVec(prometheus.CounterOpts{Name: "upf_buffer_discarded_packets_total", Help: "Buffering packets discarded by overflow, expiry, cancellation or removed ingress"}, []string{"reason"})
)

// Sample monotonic kernel counters independently of consumption. Occupancy
// includes admitted records still waiting in the ring. Delta updates also let
// independent PFCP endpoints share the process's gauge without overwriting it.
func (buffering *PacketBuffering) sampleMetrics() {
	buffering.metricsMu.Lock()
	defer buffering.metricsMu.Unlock()
	retained, overflow, canceled, err := buffering.plane.BufferPoolMetrics()
	if err != nil {
		buffering.fail(err)
		return
	}
	bufferRetainedPackets.Add(float64(int64(retained) - int64(buffering.metricsRetained)))
	if overflow >= buffering.metricsOverflow {
		bufferDiscardedPackets.WithLabelValues("overflow").Add(float64(overflow - buffering.metricsOverflow))
	}
	if canceled >= buffering.metricsCanceled {
		bufferDiscardedPackets.WithLabelValues("cancellation").Add(float64(canceled - buffering.metricsCanceled))
	}
	buffering.metricsRetained, buffering.metricsOverflow, buffering.metricsCanceled = retained, overflow, canceled
	// Publish the bounded label set even before the first retained expiry.
	bufferDiscardedPackets.WithLabelValues("expiry").Add(0)
	bufferDiscardedPackets.WithLabelValues("ingress_removed").Add(0)
}
