//go:build !linux

package ebpf

import (
	"context"
	"errors"

	cilium "github.com/cilium/ebpf"
)

func (b *BpfObjects) RenderBufferedPacket(record BufferRecord, far uint32) (RenderedBuffer, error) {
	return RenderedBuffer{}, errors.New("buffer rendering requires Linux")
}

func (b *BpfObjects) discardBufferRender(command BufferCommand) error { return nil }

func (b *BpfObjects) prepareBufferAdmission() error {
	return errors.New("buffer admission requires Linux")
}

func (b *BpfObjects) bufferControlProgram() (*cilium.Program, error) {
	return nil, errors.New("buffer control requires Linux")
}

// StartBufferPrograms completes immediately on unsupported operating systems.
func (b *BpfObjects) StartBufferPrograms(_ context.Context) <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
