package main

import (
	"testing"

	kernel "github.com/cilium/ebpf"
	"github.com/gomaja-labs/go-eupf/cmd/config"
)

func TestMemoryBudgetReservesGrowingMapCapacity(t *testing.T) {
	for _, entries := range []uint32{2048, 131070} {
		reserve, err := growingMapMemory(
			&kernel.MapInfo{Type: kernel.Hash, MaxEntries: entries, KeySize: 4, ValueSize: 8},
			&kernel.MapInfo{Type: kernel.Hash, MaxEntries: entries, KeySize: 4, ValueSize: 8},
			&kernel.MapInfo{Type: kernel.LPMTrie, MaxEntries: entries, KeySize: 20, ValueSize: 3728})
		if err != nil {
			t.Fatal(err)
		}
		if entries == 2048 && reserve != 23<<20 {
			t.Fatalf("default map reserve %d", reserve)
		}
		c := config.UpfConfig{MaxSessions: entries / 2}
		_, err = c.PFCPMemoryPlan(512<<20, (19<<20)+reserve)
		if (err != nil) != (entries == 131070) {
			t.Fatalf("entries %d reserve %d: %v", entries, reserve, err)
		}
	}
}
