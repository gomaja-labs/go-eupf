package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryBudgetIncludesSharedReplayAndKernelBaseline(t *testing.T) {
	c := UpfConfig{MaxSessions: 1024, PfcpReplayMemoryMiB: 64}
	if _, err := c.PFCPMemoryPlan(128*mib, 25*mib); err == nil {
		t.Fatal("accepted chart limit smaller than replay plus baseline")
	}
	if soft, err := c.PFCPMemoryPlan(512*mib, 25*mib); err != nil || soft != 409141248 {
		t.Fatalf("soft limit %d: %v", soft, err)
	}
	if _, err := c.PFCPMemoryPlan(512*mib, 300*mib); err == nil {
		t.Fatal("ignored larger measured kernel/map baseline")
	}
	if soft, err := c.PFCPMemoryPlan(0, 200*mib); err != nil || soft != 0 {
		t.Fatal("unlimited host rejected")
	}
}

func TestCgroupMemoryLimits(t *testing.T) {
	for _, tc := range []struct {
		limit string
		want  int64
		bad   bool
	}{{"max", 0, false}, {"536870912", 512 * mib, false}, {"bad", 0, true}, {"-1", 0, true}} {
		t.Run(tc.limit, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "memory.max"), []byte(tc.limit), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "memory.current"), []byte("26214400"), 0600); err != nil {
				t.Fatal(err)
			}
			state, err := resolveCgroupMemory("0::/", "1 0 0:1 / "+root+" rw - cgroup2 cgroup rw")
			limit, current := state.Limit, state.Current
			if (err != nil) != tc.bad || !tc.bad && (limit != tc.want || current != 25*mib) {
				t.Fatalf("limit %d current %d: %v", limit, current, err)
			}
		})
	}
}

func TestMemoryBudgetReservesLiveSessionsAndTheirGC(t *testing.T) {
	for _, sessions := range []uint32{1, 1024, 65535, 1 << 20} {
		c := UpfConfig{MaxSessions: sessions}
		needed := 448*mib + int64(sessions)*32768 + c.BufferMemoryReserve() + c.UsageWindowMemoryReserve() + c.BufferKernelMemoryReserve()
		if _, err := c.PFCPMemoryPlan(needed-1, 0); err == nil {
			t.Fatalf("sessions %d: omitted per-session memory", sessions)
		}
		if soft, err := c.PFCPMemoryPlan(needed, 0); err != nil || soft != needed-96*mib-c.BufferKernelMemoryReserve() {
			t.Fatalf("sessions %d soft %d: %v", sessions, soft, err)
		}
	}
	c := UpfConfig{}
	if _, err := c.PFCPMemoryPlan(512*mib, 0); err == nil {
		t.Fatal("unset sessions did not use standalone default")
	}
}
