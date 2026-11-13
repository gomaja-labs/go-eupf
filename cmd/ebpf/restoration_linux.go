//go:build linux

package ebpf

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"golang.org/x/sys/unix"
)

// TS 23.527 V20.0.0 clause 4.3.2 and TS 23.007 V19.2.0 clauses
// 16.1A.4/17.1b.1: start before XDP attachment, using the same monotonic
// clock as bpf_ktime_get_ns. Wall-clock corrections cannot shorten the hold.
func configureGTPRestoration(spec *ebpf.CollectionSpec) error {
	var deadline uint64
	if period := config.Conf.RestorationPeriod; period != 0 {
		var now unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
			return fmt.Errorf("read GTP restoration clock: %w", err)
		}
		deadline = uint64(now.Nano()) + uint64(period)*uint64(time.Second)
	}
	if err := spec.Variables["gtp_error_suppress_until"].Set(deadline); err != nil {
		return fmt.Errorf("set GTP restoration deadline: %w", err)
	}
	return nil
}
