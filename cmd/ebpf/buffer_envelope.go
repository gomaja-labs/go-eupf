package ebpf

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

// One secret per process authenticates private generic-XDP continuations. Each
// dataplane owns a read-only copy; the secret is never exported through metrics.
var bufferProcessToken = sync.OnceValues(func() (uint64, error) {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint64(bytes[:]), nil
})

func (b *BpfObjects) configureBufferToken() error {
	token, err := bufferProcessToken()
	if err != nil {
		return err
	}
	if err := b.BufferToken.Put(uint32(0), token); err != nil {
		return err
	}
	return b.BufferToken.Freeze()
}

// BufferKernelEnvelope wraps the complete rendered frame for generic XDP.
// The outer MAC addresses preserve the original packet type on kernel ingress.
func (b *BpfObjects) BufferKernelEnvelope(frame []byte, ingress uint32) ([]byte, error) {
	if len(frame) < 14 || ingress == 0 {
		return nil, errors.New("invalid kernel continuation frame or ingress")
	}
	var token uint64
	if err := b.BufferToken.Lookup(uint32(0), &token); err != nil {
		return nil, err
	}
	wrapped := make([]byte, 30+len(frame))
	copy(wrapped[:12], frame[:12])
	binary.BigEndian.PutUint16(wrapped[12:], 0x88b5)
	binary.NativeEndian.PutUint32(wrapped[14:], 0x42554646)
	binary.NativeEndian.PutUint32(wrapped[18:], ingress)
	binary.NativeEndian.PutUint64(wrapped[22:], token)
	copy(wrapped[30:], frame)
	return wrapped, nil
}

// BufferContinuationCounts returns authenticated and rejected envelope counts.
func (b *BpfObjects) BufferContinuationCounts() (passed, dropped uint64, err error) {
	var counters []struct{ Passed, Dropped uint64 }
	if err := b.BufferContinuationStat.Lookup(uint32(0), &counters); err != nil {
		return 0, 0, err
	}
	for _, count := range counters {
		passed += count.Passed
		dropped += count.Dropped
	}
	return passed, dropped, nil
}
