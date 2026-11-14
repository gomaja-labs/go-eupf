//go:build linux

package core

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// Linux v5.15 net/core/dev.c:netif_rx_internal queues a packet to the current
// CPU when RPS is disabled. The private veth has no RPS configuration. Keep
// the sole output worker on one CPU so sequential sends cannot enter different
// receive backlogs. This orders hand-over, not completion of kernel output.
func pinBufferOutputThread() (func() error, error) {
	runtime.LockOSThread()
	var previous unix.CPUSet
	if err := unix.SchedGetaffinity(0, &previous); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("read buffer output affinity: %w", err)
	}
	var selected unix.CPUSet
	for cpu := range 1024 {
		if previous.IsSet(cpu) {
			selected.Set(cpu)
			break
		}
	}
	if err := unix.SchedSetaffinity(0, &selected); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("pin buffer output affinity: %w", err)
	}
	return func() error {
		if err := unix.SchedSetaffinity(0, &previous); err != nil {
			// Exiting this locked goroutine retires the thread, so a restricted
			// affinity cannot escape into the runtime's reusable thread pool.
			return fmt.Errorf("restore buffer output affinity: %w", err)
		}
		runtime.UnlockOSThread()
		return nil
	}, nil
}
