package core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PfcpReplayDrops counts new requests deferred to protect retained outcomes.
var PfcpReplayDrops = promauto.NewCounter(prometheus.CounterOpts{Name: "upf_pfcp_replay_capacity_drops_total", Help: "Cacheable requests dropped for retransmission to protect retained outcomes"})

// PfcpReportFailures counts unsuccessful terminal report transfers.
var PfcpReportFailures = promauto.NewCounterVec(prometheus.CounterOpts{Name: "upf_pfcp_report_failures_total", Help: "Session Report procedures that did not deliver their information"}, []string{"outcome"})

// PfcpUndeliveredUsage counts octets whose failed report outlived its URR.
var PfcpUndeliveredUsage = promauto.NewCounter(prometheus.CounterOpts{Name: "upf_pfcp_undelivered_usage_octets_total", Help: "Undelivered usage octets belonging to removed or replaced URRs"})

// PfcpCleanupPending counts invalidated session contexts awaiting deletion.
var PfcpCleanupPending = promauto.NewGauge(prometheus.GaugeOpts{Name: "upf_pfcp_cleanup_sessions", Help: "Invalidated PFCP session contexts awaiting rule cleanup"})

// PfcpFinalUsageWait measures each response's wait for final-usage reclamation.
var PfcpFinalUsageWait = promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "upf_pfcp_final_usage_wait_seconds", Help: "Time a PFCP response waits for its final-usage grace completion", Buckets: []float64{0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 3}}, []string{"message_type"})
