// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"sync"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

type statisticsMap interface {
	Lookup(key, valueOut any) error
}

// dataplaneCollector serializes snapshots and counter history across concurrent
// scrapes. Each map is read once; every CPU's packet and XDP counters come from
// the same lookup. The two separate kernel maps are not an atomic snapshot.
type dataplaneCollector struct {
	mu                    sync.Mutex
	packets, routes       statisticsMap
	actions               [5]*prometheus.Desc
	rx, route, suppressed *prometheus.Desc
	previousPackets       [13]uint64
	previousRoutes        [6]uint64
	packetTotals          [13]float64
	routeTotals           [6]float64
}

func newDataplaneCollector(packets, routes statisticsMap) *dataplaneCollector {
	return &dataplaneCollector{
		packets: packets, routes: routes,
		actions: [5]*prometheus.Desc{
			prometheus.NewDesc("upf_xdp_aborted", "The total number of aborted packets", nil, nil),
			prometheus.NewDesc("upf_xdp_drop", "The total number of dropped packets", nil, nil),
			prometheus.NewDesc("upf_xdp_pass", "The total number of passed packets", nil, nil),
			prometheus.NewDesc("upf_xdp_tx", "The total number of transmitted packets", nil, nil),
			prometheus.NewDesc("upf_xdp_redirect", "The total number of redirected packets", nil, nil),
		},
		rx:    prometheus.NewDesc("upf_rx", "The total number of received packets", []string{"packet_type"}, nil),
		route: prometheus.NewDesc("upf_route", "The total number of packets routed", []string{"packet_type"}, nil),
		// TS 23.527 V20.0.0 clause 4.3.2: count the startup restoration
		// guard separately from diagnostic rate limiting.
		suppressed: prometheus.NewDesc("upf_gtp_error_indications_suppressed_total", "Unknown-tunnel G-PDUs discarded without Error Indication during startup restoration", nil, nil),
	}
}

func (c *dataplaneCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range c.actions {
		ch <- desc
	}
	ch <- c.rx
	ch <- c.route
	ch <- c.suppressed
}

func (c *dataplaneCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	actions := c.snapshot()
	for i, desc := range c.actions {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(actions[i]))
	}
	for i, label := range [...]string{"arp", "icmp", "icmp6", "ip4", "ip6", "tcp", "udp", "other", "gtp-echo", "gtp-pdu", "gtp-other", "gtp-unexp"} {
		ch <- prometheus.MustNewConstMetric(c.rx, prometheus.CounterValue, c.packetTotals[i], label)
	}
	for i, label := range [...]string{"ip4-ok", "ip4-error-drop", "ip4-error-pass", "ip6-ok", "ip6-error-drop", "ip6-error-pass"} {
		ch <- prometheus.MustNewConstMetric(c.route, prometheus.CounterValue, c.routeTotals[i], label)
	}
	ch <- prometheus.MustNewConstMetric(c.suppressed, prometheus.CounterValue, c.packetTotals[12])
}

// snapshot requires mu. Preserve the delta/reset handling: an unchanged absolute
// counter adds nothing; a lower counter contributes its post-reset value.
func (c *dataplaneCollector) snapshot() [5]uint64 {
	var packets []ebpf.IpEntrypointUpfStatistic
	if err := c.packets.Lookup(uint32(0), &packets); err != nil {
		log.Warn().Err(err).Msg("Failed to read packet statistics")
		packets = nil
	}
	var actions [5]uint64
	var currentPackets [13]uint64
	for _, p := range packets {
		for i := range actions {
			actions[i] += p.XdpActions[i]
		}
		values := [...]uint64{p.UpfCounters.RxArp, p.UpfCounters.RxIcmp, p.UpfCounters.RxIcmp6,
			p.UpfCounters.RxIp4, p.UpfCounters.RxIp6, p.UpfCounters.RxTcp, p.UpfCounters.RxUdp,
			p.UpfCounters.RxOther, p.UpfCounters.RxGtpEcho, p.UpfCounters.RxGtpPdu,
			p.UpfCounters.RxGtpOther, p.UpfCounters.RxGtpUnexp, p.UpfCounters.GtpErrorSuppressed}
		for i, value := range values {
			currentPackets[i] += value
		}
	}
	for i, value := range currentPackets {
		c.packetTotals[i] += counterDelta(value, c.previousPackets[i])
	}
	c.previousPackets = currentPackets

	var routes []ebpf.IpEntrypointRouteStat
	if err := c.routes.Lookup(uint32(0), &routes); err != nil {
		log.Warn().Err(err).Msg("Failed to read route statistics")
		routes = nil
	}
	var currentRoutes [6]uint64
	for _, r := range routes {
		values := [...]uint64{r.FibLookupIp4Ok, r.FibLookupIp4ErrorDrop, r.FibLookupIp4ErrorPass,
			r.FibLookupIp6Ok, r.FibLookupIp6ErrorDrop, r.FibLookupIp6ErrorPass}
		for i, value := range values {
			currentRoutes[i] += value
		}
	}
	for i, value := range currentRoutes {
		c.routeTotals[i] += counterDelta(value, c.previousRoutes[i])
	}
	c.previousRoutes = currentRoutes
	return actions
}

func counterDelta(current, previous uint64) float64 {
	if current >= previous {
		return float64(current - previous)
	}
	return float64(current)
}
