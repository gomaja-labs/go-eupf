package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const mib = int64(1 << 20)

// PFCPMemoryPlan reserves the measured startup/map baseline, two replay budgets
// for GC, all three originated queues, and transient request/encoding headroom.
// Baseline includes kernel memory charged to the container, not just Go RSS.
// The minimum baseline covers the default 1024-session maps and startup peak;
// a larger observed charge increases it rather than being hidden by that floor.
func (c *UpfConfig) PFCPMemoryPlan(limit, baseline int64) (softLimit int64, err error) {
	if limit <= 0 {
		return 0, nil
	}
	budget := int64(c.PfcpReplayMemoryMiB)
	if budget == 0 {
		budget = 128
	}
	baseline = max(baseline, 64*mib)
	const originated = 3 * 16 * mib
	const transient = 32 * mib
	needed := baseline + 2*budget*mib + originated + transient
	if limit < needed {
		return 0, fmt.Errorf("container memory limit %d bytes cannot fit PFCP replay budget plus startup/map baseline: need at least %d bytes (baseline %d)", limit, needed, baseline)
	}
	return limit - baseline - transient, nil
}

// CgroupMemory reads the container's hard limit and current charge. cgroup v2
// includes BPF map/kernel charges in memory.current. v1 uses the memory
// controller's corresponding files. A missing controller means no known limit.
func CgroupMemory(root string) (limit, current int64, err error) {
	read := func(name string) (int64, error) {
		data, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			return 0, e
		}
		text := strings.TrimSpace(string(data))
		if text == "max" {
			return 0, nil
		}
		v, e := strconv.ParseInt(text, 10, 64)
		if e != nil || v < 0 {
			return 0, fmt.Errorf("invalid cgroup memory value in %s", name)
		}
		if v >= 1<<60 {
			return 0, nil
		}
		return v, nil
	}
	limit, err = read("memory.max")
	usage := "memory.current"
	if os.IsNotExist(err) {
		limit, err = read("memory/memory.limit_in_bytes")
		usage = "memory/memory.usage_in_bytes"
	}
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	current, err = read(usage)
	return limit, current, err
}
