package config

import (
	"fmt"
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
