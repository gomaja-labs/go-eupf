//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"

	cilium "github.com/cilium/ebpf"
)

// RenderBufferedPacket applies forwarding to an already processed packet.
// The caller pins the FAR slot until all rendering and transmission I/O ends.
func (b *BpfObjects) RenderBufferedPacket(record BufferRecord, far uint32) (RenderedBuffer, error) {
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	if b.UpfIpEntrypointFunc == nil || b.UpfIpEntrypointFunc.FD() < 0 || len(record.Packet) < 14 || len(record.Packet) > BufferFrameSize || record.Kind < 1 || record.Kind > 3 || record.Cookie == 0 || far == 0 {
		return RenderedBuffer{}, errors.New("invalid buffered render request")
	}
	collection, err := b.loadBufferRendererLocked()
	if err != nil {
		return RenderedBuffer{}, err
	}
	key := renderKey{SessionID: record.SessionID, Cookie: record.Cookie, Sequence: record.Sequence, Lane: record.Lane}
	var saved renderResult
	err = collection.Maps["buffer_rendered"].Lookup(key, &saved)
	if err != nil && !errors.Is(err, cilium.ErrKeyNotExist) {
		return RenderedBuffer{}, err
	}
	if err == nil && saved.Status == 2 {
		return saved.packet()
	}
	if err == nil && saved.Status != 0 {
		return RenderedBuffer{}, errors.New("previous buffered rendering did not complete")
	}
	if errors.Is(err, cilium.ErrKeyNotExist) {
		saved.IngressIfindex = record.IngressIfindex
		saved.Reserved = uint64(record.PDRID)
		if err := collection.Maps["buffer_rendered"].Update(key, &saved, cilium.UpdateNoExist); err != nil {
			return RenderedBuffer{}, err
		}
	}
	if err := collection.Maps["buffer_current"].Put(uint32(0), key); err != nil {
		return RenderedBuffer{}, err
	}
	data := bufferRenderInput(record, far)
	inputContext := struct{ Data, DataEnd, DataMeta, IngressIfindex, RxQueueIndex, EgressIfindex uint32 }{DataEnd: uint32(len(data)), IngressIfindex: record.IngressIfindex}
	_, runErr := collection.Programs["upf_buffer_render_func"].Run(&cilium.RunOptions{Data: data, Context: &inputContext, Repeat: 1})
	if err := collection.Maps["buffer_rendered"].Lookup(key, &saved); err != nil {
		return RenderedBuffer{}, errors.Join(runErr, err)
	}
	if saved.Status == 2 {
		return saved.packet()
	}
	if runErr != nil {
		return RenderedBuffer{}, fmt.Errorf("render buffered packet: %w", runErr)
	}
	return RenderedBuffer{}, errors.New("buffer renderer rejected stale or malformed input")
}

func bufferRenderInput(record BufferRecord, far uint32) []byte {
	data := make([]byte, 64+len(record.Packet))
	binary.LittleEndian.PutUint64(data, record.SessionID)
	binary.LittleEndian.PutUint64(data[8:], record.Cookie)
	binary.LittleEndian.PutUint64(data[16:], record.Sequence)
	binary.LittleEndian.PutUint64(data[24:], uint64(record.PDRID))
	binary.LittleEndian.PutUint32(data[32:], record.Lane)
	binary.LittleEndian.PutUint32(data[36:], far)
	binary.LittleEndian.PutUint32(data[40:], uint32(len(record.Packet)))
	binary.LittleEndian.PutUint16(data[48:], record.Marking)
	data[50], data[51], data[52], data[53], data[54], data[55] = record.Kind, record.NR, record.SourceInterface, record.OuterRemoval, record.OuterRemovalPresent, record.ExtensionDeletion
	copy(data[64:], record.Packet)
	return data
}
