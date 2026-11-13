//go:build linux

package core

import (
	"time"

	"golang.org/x/sys/unix"
)

func bufferClockBase() (time.Time, uint64, error) {
	now := time.Now()
	var stamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp); err != nil {
		return time.Time{}, 0, err
	}
	return now, uint64(stamp.Nano()), nil
}
