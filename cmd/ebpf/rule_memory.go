package ebpf

import (
	"fmt"
	"unsafe"

	cilium "github.com/cilium/ebpf"
)

// sharedRuleMemory is owned by ruleMutex, including unmapping during Close.
// Only unreachable, exclusively reserved versions may be initialized here.
// The subsequent locked descriptor publication makes the completed image
// visible; retired slots still require the ordinary kernel reader grace.
// Linux array mappings: https://docs.kernel.org/bpf/map_array.html
// Publication ordering: https://docs.kernel.org/core-api/wrappers/memory-barriers.html
// The mapping has explicit ownership rather than a garbage-collected lifetime.
type sharedRuleMemory struct {
	object            *cilium.Map
	data              []byte
	valueSize, stride uint64
	entries           uint32
}

func newSharedRuleMemory(object *cilium.Map, nativeSize uintptr) (*sharedRuleMemory, error) {
	info, err := object.Info()
	if err != nil {
		return nil, err
	}
	if info.Type != cilium.Array || uint64(info.ValueSize) != uint64(nativeSize) {
		return nil, fmt.Errorf("rule array layout: native %d, kernel %d", nativeSize, info.ValueSize)
	}
	stride := (uint64(info.ValueSize) + 7) &^ uint64(7)
	length := stride * uint64(info.MaxEntries)
	if length == 0 || length > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("rule mapping size %d is unavailable", length)
	}
	data, err := mapRuleMemory(object.FD(), int(length))
	if err != nil {
		return nil, err
	}
	return &sharedRuleMemory{object: object, data: data, valueSize: uint64(info.ValueSize), stride: stride, entries: info.MaxEntries}, nil
}
func (memory *sharedRuleMemory) close() error {
	if memory == nil || memory.data == nil {
		return nil
	}
	if err := unmapRuleMemory(memory.data); err != nil {
		return err
	}
	memory.data = nil
	return nil
}

type sharedRuleValue interface {
	IpEntrypointPdrBucket | IpEntrypointFarInfo
}

func storeSharedRule[T sharedRuleValue](memory *sharedRuleMemory, slot uint32, value *T) error {
	if memory == nil || memory.data == nil || memory.object.FD() < 0 {
		return fmt.Errorf("rule mapping is closed")
	}
	size := uint64(unsafe.Sizeof(*value))
	if slot == 0 || slot >= memory.entries || size != memory.valueSize {
		return fmt.Errorf("invalid rule mapping slot %d or layout %d", slot, size)
	}
	offset := uint64(slot) * memory.stride
	copy(memory.data[offset:offset+size], unsafe.Slice((*byte)(unsafe.Pointer(value)), int(size)))
	return nil
}
