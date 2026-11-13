package ebpf

import (
	"encoding/binary"
	"fmt"

	cilium "github.com/cilium/ebpf"
)

func (b *BpfObjects) bucketKey(m *cilium.Map, key interface{}) (uint32, uint32) {
	if m == b.PdrMapTeidIp4 {
		return key.(uint32), 0
	}
	ip := key.([4]byte)
	return binary.LittleEndian.Uint32(ip[:]), 1
}
func (b *BpfObjects) releaseBucket(id uint32) {
	b.bucketMutex.Lock()
	defer b.bucketMutex.Unlock()
	b.bucketIDs.Release(id)
}
func (tx *ruleTransaction) allocateBucket() (uint32, error) {
	b := tx.objects
	allocate := func() (uint32, error) {
		b.bucketMutex.Lock()
		defer b.bucketMutex.Unlock()
		return b.bucketIDs.GetNext()
	}
	id, err := allocate()
	if err != nil {
		// Bound outstanding versions without delaying ordinary PFCP requests. Only
		// pool exhaustion waits for already queued readers, not a time-based guess.
		if err = b.grace.wait(); err != nil {
			return 0, err
		}
		id, err = allocate()
	}
	if err == nil {
		tx.allocatedBuckets = append(tx.allocatedBuckets, id)
	}
	return id, err
}
func (b *BpfObjects) lookupPDR(m *cilium.Map, key interface{}, value *IpEntrypointPdrInfo, exact bool) error {
	if m == b.PdrMapDownlinkIp6 {
		if exact {
			return lookupRuleValue(m, key, value)
		}
		return m.Lookup(key, value)
	}
	var index IpEntrypointPdrIndex
	if err := m.Lookup(key, &index); err != nil {
		return err
	}
	var bucket IpEntrypointPdrBucket
	if err := b.PdrBuckets.Lookup(index.Slot, &bucket); err != nil {
		return err
	}
	k, kind := b.bucketKey(m, key)
	if index.Slot == 0 || bucket.Key != k || bucket.Kind != kind {
		return fmt.Errorf("PDR slot key mismatch")
	}
	*value = bucket.Info
	return nil
}

// LookupUplinkPDR copies a stable bucket. Diagnostic callers hold LockRuleSnapshot
// through lookup and decoding, so a retired slot cannot be reused underneath it.
func (b *BpfObjects) LookupUplinkPDR(key uint32, value *IpEntrypointPdrInfo) error {
	return b.lookupPDR(b.PdrMapTeidIp4, key, value, false)
}
