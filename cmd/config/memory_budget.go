package config

import "fmt"

const mib = int64(1 << 20)

// PFCPMemoryPlan reserves the measured startup/map baseline, two replay budgets
// for GC, live sessions and their GC headroom, all three originated queues,
// and transient request/encoding headroom.
// Baseline includes kernel memory charged to the container, not just Go RSS.
// The minimum baseline covers the default 1024-session maps and startup peak;
// a larger observed charge increases it rather than being hidden by that floor.
func (c *UpfConfig) PFCPMemoryPlan(limit, baseline int64) (softLimit int64, err error) {
	if err := c.ValidateBuffering(); err != nil {
		return 0, err
	}
	if limit <= 0 {
		return 0, nil
	}
	budget := int64(c.PfcpReplayMemoryMiB)
	if budget == 0 {
		budget = 128
	}
	baseline = max(baseline, 64*mib)
	// Each endpoint bounds reliable-request payloads and detached local-release
	// usage contexts independently at 16 MiB. They can coexist until outcomes.
	const originated = 3 * 32 * mib
	const transient = 32 * mib
	sessions := c.MaxSessions
	if sessions == 0 {
		sessions = 65535
	}
	// Real eBPF publication plus PFCP state retained 12,071 bytes/session for
	// four PDRs, three FARs, two QERs and two URRs (8192 synthetic sessions).
	// Round live state to 16 KiB and reserve it twice for GC and replacement.
	sessionMemory := int64(sessions) * (32 << 10)
	buffers, windows := c.BufferMemoryReserve(), c.UsageWindowMemoryReserve()
	kernelBuffers := c.BufferKernelMemoryReserve()
	needed := baseline + 2*budget*mib + sessionMemory + originated + transient + buffers + windows + kernelBuffers
	if limit < needed {
		return 0, fmt.Errorf("container memory limit %d bytes cannot fit replay, sessions, buffers and startup/map baseline: need at least %d bytes (baseline %d, sessions %d, buffers %d, buffer kernel %d, usage windows %d)", limit, needed, baseline, sessionMemory, buffers, kernelBuffers, windows)
	}
	return limit - baseline - transient - kernelBuffers, nil
}
