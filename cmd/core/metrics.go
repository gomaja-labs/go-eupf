// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"net/http"

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

	UpfPfcpSessions          prometheus.GaugeFunc
	UpfPfcpAssociationsTotal prometheus.GaugeFunc

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
	collector := newDataplaneCollector(stats.BpfObjects.UpfExtStat, stats.BpfObjects.UpfRouteStat)
	prometheus.MustRegister(collector)

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

	prometheus.MustRegister(UpfPfcpSessions)
	prometheus.MustRegister(UpfPfcpAssociationsTotal)
}
