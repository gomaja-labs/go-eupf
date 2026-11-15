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
		needed := 352*mib + 3*(16*mib+c.LocalReleaseMemoryReserve()) + int64(sessions)*32768 + c.BufferMemoryReserve() + c.UsageWindowMemoryReserve() + c.BufferKernelMemoryReserve()
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

func TestLocalReleaseReserveIncludesOneDenseSessionAndAllContextHeaders(t *testing.T) {
	for _, capacity := range []uint32{1, 2048, 8192, 16384, 2097152} {
		c := UpfConfig{UrrMapSize: capacity}
		reserve := c.LocalReleaseMemoryReserve()
		if reserve < 16*mib || reserve < 2048*(int64(capacity)+128) {
			t.Fatalf("URR capacity %d cannot fit one dense session: %d", capacity, reserve)
		}
	}
	c := UpfConfig{MaxSessions: 1024}
	if c.LocalReleaseMemoryReserve() != 16*mib {
		t.Fatal("chart reserve changed")
	}
	c = UpfConfig{MaxSessions: 16384}
	if c.LocalReleaseMemoryReserve() < 2048*(32768+128) {
		t.Fatal("automatic map capacity omitted")
	}
}
