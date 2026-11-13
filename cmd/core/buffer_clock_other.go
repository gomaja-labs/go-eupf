//go:build !linux

package core

import (
	"errors"
	"time"
)

func bufferClockBase() (time.Time, uint64, error) {
	return time.Time{}, 0, errors.New("packet buffering requires Linux")
}
