// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"

	cilium "github.com/cilium/ebpf"
)

// RenderedBuffer is a completed packet rewrite and its resolved egress.
// Rendering alone never transmits a frame.
type RenderedBuffer struct {
	Frame   []byte
	Ifindex uint32
	Action  uint32
}

// RenderBufferedPacket applies forwarding to an already processed packet.
// The caller pins the FAR slot until all rendering and transmission I/O ends.
func (b *BpfObjects) RenderBufferedPacket(record BufferRecord, far uint32) (RenderedBuffer, error) {
	if b.UpfBufferRenderFunc == nil || b.UpfBufferRenderFunc.FD() < 0 || len(record.Packet) < 14 || len(record.Packet) > BufferFrameSize || record.Kind < 1 || record.Kind > 3 || record.Cookie == 0 || far == 0 {
		return RenderedBuffer{}, errors.New("invalid buffered render request")
	}
	data := make([]byte, 64+len(record.Packet))
	binary.LittleEndian.PutUint64(data, record.SessionID)
	binary.LittleEndian.PutUint64(data[8:], record.Cookie)
	binary.LittleEndian.PutUint64(data[16:], record.Sequence)
	binary.LittleEndian.PutUint32(data[32:], record.Lane)
	binary.LittleEndian.PutUint32(data[36:], far)
	binary.LittleEndian.PutUint32(data[40:], uint32(len(record.Packet)))
	binary.LittleEndian.PutUint16(data[48:], record.Marking)
	data[50], data[51], data[52], data[53], data[54], data[55] = record.Kind, record.NR, record.SourceInterface, record.OuterRemoval, record.OuterRemovalPresent, record.ExtensionDeletion
	copy(data[64:], record.Packet)
	inputContext := struct{ Data, DataEnd, DataMeta, IngressIfindex, RxQueueIndex, EgressIfindex uint32 }{DataEnd: uint32(len(data)), IngressIfindex: record.IngressIfindex}
	opts := cilium.RunOptions{Data: data, DataOut: make([]byte, len(data)+512), Context: &inputContext, Repeat: 1}
	action, err := b.UpfBufferRenderFunc.Run(&opts)
	if err != nil {
		return RenderedBuffer{}, fmt.Errorf("render buffered packet: %w", err)
	}
	if action != 2 || len(opts.DataOut) < 78 {
		return RenderedBuffer{}, fmt.Errorf("buffer renderer rejected stale or malformed packet: action=%d length=%d", action, len(opts.DataOut))
	}
	return RenderedBuffer{Frame: opts.DataOut[64:], Ifindex: binary.LittleEndian.Uint32(opts.DataOut[40:]), Action: binary.LittleEndian.Uint32(opts.DataOut[60:])}, nil
}
