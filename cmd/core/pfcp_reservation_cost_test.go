package core

import (
	"runtime"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
)

func TestReservationCostIndependentOfPoolSize(t *testing.T) {
	conn := newProtocolConnection(t)
	for _, pool := range []struct {
		cidr  string
		teids uint32
	}{{"192.0.2.0/30", 4}, {"10.60.0.0/16", 65535}} {
		resources, err := service.NewResourceManager(pool.cidr, pool.teids)
		if err != nil {
			t.Fatal(err)
		}
		conn.ResourceManager = resources
		allocations := testing.AllocsPerRun(3, func() {
			_, finish := conn.prepareSessionMutation(NewSession(11, 77, "", "", false), updateSessionMutation)
			if err := finish(false); err != nil {
				t.Fatal(err)
			}
		})
		t.Logf("pool=%s TEIDs=%d allocations=%.0f", pool.cidr, pool.teids, allocations)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for range 64 {
			_, finish := conn.prepareSessionMutation(NewSession(11, 77, "", "", false), updateSessionMutation)
			if err := finish(false); err != nil {
				t.Fatal(err)
			}
		}
		runtime.ReadMemStats(&after)
		bytesPerRequest := (after.TotalAlloc - before.TotalAlloc) / 64
		t.Logf("reservation bytes per request=%d", bytesPerRequest)
		if bytesPerRequest > 32768 {
			t.Errorf("reservation cost grows with pool size: %d bytes/request", bytesPerRequest)
		}
		if allocations > 100 {
			t.Errorf("request copied pool entries: %.0f allocations", allocations)
		}
	}
}
