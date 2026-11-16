//go:build !linux

package core

import (
	"errors"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

func newBufferPacketSender(_ *ebpf.BpfObjects) (packetBufferSender, error) {
	return nil, errors.New("buffered packet output requires Linux")
}

func setBufferIngressMode(_ *ebpf.BpfObjects, _ uint32) error {
	return errors.New("XDP attachments require Linux")
}
