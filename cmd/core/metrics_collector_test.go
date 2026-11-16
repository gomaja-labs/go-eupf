package core

import (
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Count the kernel boundary, not a cached getter. Multiple CPU slots must be
// summed once for every series in a scrape.
type countingStatisticsMap struct {
	reads  int
	values any
}

func (m *countingStatisticsMap) Lookup(key, out any) error {
	if key != uint32(0) {
		return fmt.Errorf("statistics key = %v, want uint32(0)", key)
	}
	m.reads++
	switch values := m.values.(type) {
	case []ebpf.IpEntrypointUpfStatistic:
		*out.(*[]ebpf.IpEntrypointUpfStatistic) = values
	case []ebpf.IpEntrypointRouteStat:
		*out.(*[]ebpf.IpEntrypointRouteStat) = values
	default:
		return fmt.Errorf("unsupported statistics fixture %T", m.values)
	}
	return nil
}

func TestDataplaneCollectorReadsEachMapOnce(t *testing.T) {
	packets := &countingStatisticsMap{values: []ebpf.IpEntrypointUpfStatistic{
		statisticsPacket(ebpf.UpfCounters{RxArp: 1, RxIcmp: 2, RxIcmp6: 3, RxIp4: 4, RxIp6: 5, RxTcp: 6, RxUdp: 7, RxOther: 8, RxGtpEcho: 9, RxGtpPdu: 10, RxGtpOther: 11, RxGtpUnexp: 12, GtpErrorSuppressed: 13}),
		statisticsPacket(ebpf.UpfCounters{RxIp4: 20, GtpErrorSuppressed: 30}),
	}}
	values := packets.values.([]ebpf.IpEntrypointUpfStatistic)
	copy(values[0].XdpActions[:], []uint64{1, 2, 3, 4, 5})
	copy(values[1].XdpActions[:], []uint64{10, 20, 30, 40, 50})
	routes := &countingStatisticsMap{values: []ebpf.IpEntrypointRouteStat{
		{FibLookupIp4Ok: 1, FibLookupIp4ErrorDrop: 2, FibLookupIp4ErrorPass: 3, FibLookupIp6Ok: 4, FibLookupIp6ErrorDrop: 5, FibLookupIp6ErrorPass: 6},
		{FibLookupIp4Ok: 10, FibLookupIp6ErrorPass: 20},
	}}
	collector := newDataplaneCollector(packets, routes)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)
	if packets.reads != 0 || routes.reads != 0 {
		t.Fatal("Describe read the maps")
	}
	// Names, help, labels and counter types are the base's exposition, with
	// independently calculated sums for the synthetic two-CPU snapshot.
	const want = `
# HELP upf_xdp_aborted The total number of aborted packets
# TYPE upf_xdp_aborted counter
upf_xdp_aborted 11
# HELP upf_xdp_drop The total number of dropped packets
# TYPE upf_xdp_drop counter
upf_xdp_drop 22
# HELP upf_xdp_pass The total number of passed packets
# TYPE upf_xdp_pass counter
upf_xdp_pass 33
# HELP upf_xdp_tx The total number of transmitted packets
# TYPE upf_xdp_tx counter
upf_xdp_tx 44
# HELP upf_xdp_redirect The total number of redirected packets
# TYPE upf_xdp_redirect counter
upf_xdp_redirect 55
# HELP upf_rx The total number of received packets
# TYPE upf_rx counter
upf_rx{packet_type="arp"} 1
upf_rx{packet_type="icmp"} 2
upf_rx{packet_type="icmp6"} 3
upf_rx{packet_type="ip4"} 24
upf_rx{packet_type="ip6"} 5
upf_rx{packet_type="tcp"} 6
upf_rx{packet_type="udp"} 7
upf_rx{packet_type="other"} 8
upf_rx{packet_type="gtp-echo"} 9
upf_rx{packet_type="gtp-pdu"} 10
upf_rx{packet_type="gtp-other"} 11
upf_rx{packet_type="gtp-unexp"} 12
# HELP upf_route The total number of packets routed
# TYPE upf_route counter
upf_route{packet_type="ip4-ok"} 11
upf_route{packet_type="ip4-error-drop"} 2
upf_route{packet_type="ip4-error-pass"} 3
upf_route{packet_type="ip6-ok"} 4
upf_route{packet_type="ip6-error-drop"} 5
upf_route{packet_type="ip6-error-pass"} 26
# HELP upf_gtp_error_indications_suppressed_total Unknown-tunnel G-PDUs discarded without Error Indication during startup restoration
# TYPE upf_gtp_error_indications_suppressed_total counter
upf_gtp_error_indications_suppressed_total 43
`
	for scrape := 1; scrape <= 2; scrape++ {
		response := httptest.NewRecorder()
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
		normalize := func(s string) string {
			lines := strings.Split(strings.TrimSpace(s), "\n")
			sort.Strings(lines)
			return strings.Join(lines, "\n")
		}
		if response.Code != 200 || normalize(response.Body.String()) != normalize(want) {
			t.Fatalf("scrape status=%d body:\n%s\nwant:\n%s", response.Code, response.Body.String(), want)
		}
		if packets.reads != scrape || routes.reads != scrape {
			t.Fatalf("scrape %d: packet reads %d, route reads %d; want %d each", scrape, packets.reads, routes.reads, scrape)
		}
	}
}

func TestDataplaneCollectorDeltaResetAndConcurrentScrapes(t *testing.T) {
	packets := &countingStatisticsMap{values: []ebpf.IpEntrypointUpfStatistic{statisticsPacket(ebpf.UpfCounters{RxIp4: 7, GtpErrorSuppressed: 3})}}
	routes := &countingStatisticsMap{values: []ebpf.IpEntrypointRouteStat{{FibLookupIp4Ok: 5}}}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(newDataplaneCollector(packets, routes))
	assertTotals := func(rx, suppressed, route float64) {
		t.Helper()
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]float64{}
		for _, f := range families {
			for _, m := range f.Metric {
				if f.GetName() == "upf_gtp_error_indications_suppressed_total" {
					got["suppressed"] = m.GetCounter().GetValue()
				}
				for _, label := range m.Label {
					if f.GetName() == "upf_rx" && label.GetValue() == "ip4" {
						got["rx"] = m.GetCounter().GetValue()
					}
					if f.GetName() == "upf_route" && label.GetValue() == "ip4-ok" {
						got["route"] = m.GetCounter().GetValue()
					}
				}
			}
		}
		if got["rx"] != rx || got["suppressed"] != suppressed || got["route"] != route {
			t.Fatalf("totals = %v, want rx=%v suppressed=%v route=%v", got, rx, suppressed, route)
		}
	}
	assertTotals(7, 3, 5)
	assertTotals(7, 3, 5)
	packets.values = []ebpf.IpEntrypointUpfStatistic{statisticsPacket(ebpf.UpfCounters{RxIp4: 9, GtpErrorSuppressed: 4})}
	routes.values = []ebpf.IpEntrypointRouteStat{{FibLookupIp4Ok: 8}}
	assertTotals(9, 4, 8)
	// A restarted map contributes its new value, without unsigned underflow.
	packets.values = []ebpf.IpEntrypointUpfStatistic{statisticsPacket(ebpf.UpfCounters{RxIp4: 2, GtpErrorSuppressed: 1})}
	routes.values = []ebpf.IpEntrypointRouteStat{{FibLookupIp4Ok: 3}}
	assertTotals(11, 5, 11)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 4 {
				if _, err := registry.Gather(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	assertTotals(11, 5, 11)
	if packets.reads != 69 || routes.reads != 69 {
		t.Fatalf("concurrent scrapes: reads = %d/%d, want 69/69", packets.reads, routes.reads)
	}
}

func statisticsPacket(c ebpf.UpfCounters) ebpf.IpEntrypointUpfStatistic {
	var p ebpf.IpEntrypointUpfStatistic
	p.UpfCounters.RxArp = c.RxArp
	p.UpfCounters.RxIcmp = c.RxIcmp
	p.UpfCounters.RxIcmp6 = c.RxIcmp6
	p.UpfCounters.RxIp4 = c.RxIp4
	p.UpfCounters.RxIp6 = c.RxIp6
	p.UpfCounters.RxTcp = c.RxTcp
	p.UpfCounters.RxUdp = c.RxUdp
	p.UpfCounters.RxOther = c.RxOther
	p.UpfCounters.RxGtpEcho = c.RxGtpEcho
	p.UpfCounters.RxGtpPdu = c.RxGtpPdu
	p.UpfCounters.RxGtpOther = c.RxGtpOther
	p.UpfCounters.RxGtpUnexp = c.RxGtpUnexp
	p.UpfCounters.GtpErrorSuppressed = c.GtpErrorSuppressed
	return p
}
