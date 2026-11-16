//go:build linux

package core

import (
	"fmt"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	dataplane "github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

func TestSessionCollectorDuringAssociationDeletion(t *testing.T) {
	conn := &PfcpConnection{NodeAssociations: make(map[string]*NodeAssociation)}
	for i := range 128 {
		addr := fmt.Sprintf("192.0.2.1:%d", 10000+i)
		conn.NodeAssociations[addr] = NewNodeAssociation(addr, addr)
	}
	oldRegistry := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = oldRegistry }()
	RegisterMetrics(dataplane.UpfXdpActionStatistic{BpfObjects: dataplane.NewBpfObjects()}, []*PfcpConnection{conn})
	registry := prometheus.NewRegistry()
	registry.MustRegister(UpfPfcpSessions)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Go(func() {
		<-start
		for range 256 {
			if _, err := registry.Gather(); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Go(func() {
		<-start
		for i := range 128 {
			conn.DeleteAssociation(fmt.Sprintf("192.0.2.1:%d", 10000+i))
		}
	})
	close(start)
	wg.Wait()
}

func TestDataplaneCollectorKernelSnapshot(t *testing.T) {
	bpf := dataplane.NewBpfObjects()
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []uint32{
		uint32(unsafe.Sizeof(dataplane.IpEntrypointUpfStatistic{})),
		uint32(unsafe.Sizeof(dataplane.IpEntrypointRouteStat{})),
	} {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: size, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = m.Close() }()
		if bpf.UpfExtStat == nil {
			bpf.UpfExtStat = m
		} else {
			bpf.UpfRouteStat = m
		}
	}
	values := make([]dataplane.IpEntrypointUpfStatistic, ncpu)
	values[0].UpfCounters.RxIp4 = 7
	values[0].UpfCounters.GtpErrorSuppressed = 3
	values[0].XdpActions[2] = 9
	if err := bpf.UpfExtStat.Put(uint32(0), values); err != nil {
		t.Fatal(err)
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(newDataplaneCollector(bpf.UpfExtStat, bpf.UpfRouteStat))
	for range 2 {
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[string]float64)
		for _, family := range families {
			for _, metric := range family.Metric {
				name := family.GetName()
				if name == "upf_xdp_pass" || name == "upf_gtp_error_indications_suppressed_total" {
					got[name] = metric.GetCounter().GetValue()
				}
				for _, label := range metric.Label {
					if name == "upf_rx" && label.GetValue() == "ip4" {
						got[name] = metric.GetCounter().GetValue()
					}
				}
			}
		}
		if got["upf_rx"] != 7 || got["upf_xdp_pass"] != 9 || got["upf_gtp_error_indications_suppressed_total"] != 3 {
			t.Fatalf("kernel statistics = %v; want rx=7 pass=9 suppressed=3", got)
		}
	}
}
