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
