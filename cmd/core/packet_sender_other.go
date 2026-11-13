//go:build !linux

package core

import "errors"

func newBufferPacketSender() (packetBufferSender, error) {
	return nil, errors.New("buffered packet output requires Linux")
}
