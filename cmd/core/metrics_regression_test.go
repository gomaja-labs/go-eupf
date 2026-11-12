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

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(c)
	metrics, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	return metrics[0].GetMetric()[0].GetCounter().GetValue()
}

func TestGatherMetricsDoesNotCountPacketsTwice(t *testing.T) {
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
	if err := bpf.UpfExtStat.Put(uint32(0), values); err != nil {
		t.Fatal(err)
	}
	stats := dataplane.UpfXdpActionStatistic{BpfObjects: bpf}
	counter := UpfRx.WithLabelValues("ip4")
	before := counterValue(t, counter)
	GatherMetrics(stats)
	first := counterValue(t, counter)
	if first-before != 7 {
		t.Fatalf("first scrape added %v, want 7", first-before)
	}
	GatherMetrics(stats)
	if second := counterValue(t, counter); second != first {
		t.Errorf("unchanged map counted again: first %v, second %v", first, second)
	}
}

func TestSessionCollectorDuringAssociationDeletion(t *testing.T) {
	conn := &PfcpConnection{NodeAssociations: make(map[string]*NodeAssociation)}
	for i := range 128 {
		addr := fmt.Sprintf("192.0.2.1:%d", 10000+i)
		conn.NodeAssociations[addr] = NewNodeAssociation(addr, addr)
	}
	oldRegistry := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = oldRegistry }()
	RegisterMetrics(dataplane.UpfXdpActionStatistic{}, []*PfcpConnection{conn})
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
