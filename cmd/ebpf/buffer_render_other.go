//go:build !linux

package ebpf

import "errors"

func (b *BpfObjects) RenderBufferedPacket(record BufferRecord, far uint32) (RenderedBuffer, error) {
	return RenderedBuffer{}, errors.New("buffer rendering requires Linux")
}

func (b *BpfObjects) discardBufferRender(command BufferCommand) error { return nil }
