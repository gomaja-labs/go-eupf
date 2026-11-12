// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"net/http"
	"sync"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	PfcpRequestRetransmissions = promauto.NewCounterVec(prometheus.CounterOpts{Name: "upf_pfcp_retransmissions", Help: "PFCP request retransmission attempts"}, []string{"message_name"})
	PfcpRequestTimeouts        = promauto.NewCounterVec(prometheus.CounterOpts{Name: "upf_pfcp_request_timeouts", Help: "PFCP requests that exhausted the retransmission budget"}, []string{"message_name"})
	PfcpAssociationPrunes      = promauto.NewCounter(prometheus.CounterOpts{Name: "upf_pfcp_association_prunes", Help: "PFCP associations removed after the configured unreachable period"})

	PfcpMessageRx = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "upf_pfcp_rx",
		Help: "The total number of received PFCP messages",
	}, []string{"message_name"})

	PfcpMessageTx = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "upf_pfcp_tx",
		Help: "The total number of transmitted PFCP messages",
	}, []string{"message_name"})

	PfcpMessageRxErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "upf_pfcp_rx_errors",
		Help: "The total number of received PFCP messages with cause code",
	}, []string{"message_name", "cause_code"})

	UpfXdpAborted            prometheus.CounterFunc
	UpfXdpDrop               prometheus.CounterFunc
	UpfXdpPass               prometheus.CounterFunc
	UpfXdpTx                 prometheus.CounterFunc
	UpfXdpRedirect           prometheus.CounterFunc
	UpfPfcpSessions          prometheus.GaugeFunc
	UpfPfcpAssociationsTotal prometheus.GaugeFunc

	UpfRx = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "upf_rx",
		Help: "The total number of received packets",
	}, []string{"packet_type"})

	UpfRoute = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "upf_route",
		Help: "The total number of packets routed",
	}, []string{"packet_type"})

	UpfMessageRxLatency = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "upf_pfcp_rx_duration_seconds",
		Help:       "Duration of PFCP message processing in seconds",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	}, []string{"message_type"})
)

func StartMetrics(addr string) error {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(addr, nil)
	return err
}

func RegisterMetrics(stats ebpf.UpfXdpActionStatistic, conn []*PfcpConnection) {
	// Metrics for the upf_xdp_statistic (xdp_action)
	UpfXdpAborted = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "upf_xdp_aborted",
		Help: "The total number of aborted packets",
	}, func() float64 {
		return float64(stats.GetAborted())
	})

	UpfXdpDrop = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "upf_xdp_drop",
		Help: "The total number of dropped packets",
	}, func() float64 {
		return float64(stats.GetDrop())
	})

	UpfXdpPass = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "upf_xdp_pass",
		Help: "The total number of passed packets",
	}, func() float64 {
		return float64(stats.GetPass())
	})

	UpfXdpTx = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "upf_xdp_tx",
		Help: "The total number of transmitted packets",
	}, func() float64 {
		return float64(stats.GetTx())
	})

	UpfXdpRedirect = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "upf_xdp_redirect",
		Help: "The total number of redirected packets",
	}, func() float64 {
		return float64(stats.GetRedirect())
	})

	UpfPfcpSessions = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "upf_pfcp_sessions",
		Help: "The current number of PFCP sessions",
	}, func() float64 {
		sum := float64(0)
		for _, c := range conn {
			sum += float64(c.GetSessionCount())
		}
		return float64(sum)
	})

	UpfPfcpAssociationsTotal = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "upf_pfcp_associations_total",
		Help: "The current number of PFCP associations",
	}, func() float64 {
		sum := float64(0)
		for _, c := range conn {
			sum += float64(c.GetAssiciationCount())
		}
		return float64(sum)
	})

	// Register metrics
	prometheus.MustRegister(UpfXdpAborted)
	prometheus.MustRegister(UpfXdpDrop)
	prometheus.MustRegister(UpfXdpPass)
	prometheus.MustRegister(UpfXdpTx)
	prometheus.MustRegister(UpfXdpRedirect)
	prometheus.MustRegister(UpfPfcpSessions)
	prometheus.MustRegister(UpfPfcpAssociationsTotal)
}

// Packet and route metrics share one process-wide dataplane, like the metric
// vectors themselves. Serialize the previous absolute snapshot across scrapes;
// the UpfXdpActionStatistic argument is a value and cannot own this history.
var metricSnapshots struct {
	sync.Mutex
	source  *ebpf.BpfObjects
	packets ebpf.UpfCounters
	routes  ebpf.IpEntrypointRouteStat
}

func GatherMetrics(stats ebpf.UpfXdpActionStatistic) {
	metricSnapshots.Lock()
	defer metricSnapshots.Unlock()
	if metricSnapshots.source != stats.BpfObjects {
		metricSnapshots.source = stats.BpfObjects
		metricSnapshots.packets = ebpf.UpfCounters{}
		metricSnapshots.routes = ebpf.IpEntrypointRouteStat{}
	}
	packets := stats.GetUpfExtStat()
	routes := stats.GetUpfRouteStat()
	add := func(counter *prometheus.CounterVec, label string, current, previous uint64) {
		delta := current
		if current >= previous {
			delta -= previous
		}
		counter.WithLabelValues(label).Add(float64(delta))
	}
	previous := metricSnapshots.packets
	add(UpfRx, "arp", packets.RxArp, previous.RxArp)
	add(UpfRx, "icmp", packets.RxIcmp, previous.RxIcmp)
	add(UpfRx, "icmp6", packets.RxIcmp6, previous.RxIcmp6)
	add(UpfRx, "ip4", packets.RxIp4, previous.RxIp4)
	add(UpfRx, "ip6", packets.RxIp6, previous.RxIp6)
	add(UpfRx, "tcp", packets.RxTcp, previous.RxTcp)
	add(UpfRx, "udp", packets.RxUdp, previous.RxUdp)
	add(UpfRx, "other", packets.RxOther, previous.RxOther)
	add(UpfRx, "gtp-echo", packets.RxGtpEcho, previous.RxGtpEcho)
	add(UpfRx, "gtp-pdu", packets.RxGtpPdu, previous.RxGtpPdu)
	add(UpfRx, "gtp-other", packets.RxGtpOther, previous.RxGtpOther)
	add(UpfRx, "gtp-unexp", packets.RxGtpUnexp, previous.RxGtpUnexp)
	prior := metricSnapshots.routes
	add(UpfRoute, "ip4-ok", routes.FibLookupIp4Ok, prior.FibLookupIp4Ok)
	add(UpfRoute, "ip4-error-drop", routes.FibLookupIp4ErrorDrop, prior.FibLookupIp4ErrorDrop)
	add(UpfRoute, "ip4-error-pass", routes.FibLookupIp4ErrorPass, prior.FibLookupIp4ErrorPass)
	add(UpfRoute, "ip6-ok", routes.FibLookupIp6Ok, prior.FibLookupIp6Ok)
	add(UpfRoute, "ip6-error-drop", routes.FibLookupIp6ErrorDrop, prior.FibLookupIp6ErrorDrop)
	add(UpfRoute, "ip6-error-pass", routes.FibLookupIp6ErrorPass, prior.FibLookupIp6ErrorPass)
	metricSnapshots.packets = packets
	metricSnapshots.routes = routes
}
