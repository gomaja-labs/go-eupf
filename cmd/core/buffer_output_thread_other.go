//go:build !linux

package core

import "errors"

func pinBufferOutputThread() (func() error, error) {
	return nil, errors.New("buffer output affinity requires Linux")
}
