package ebpf

import (
	"encoding/binary"
	"fmt"
	"math"

	cilium "github.com/cilium/ebpf"
)

// MaxRulesPerSession is the admitted number of rules of each type in a PFCP
// session. One PDR selects at most one of the two hash-key maps.
const MaxRulesPerSession = 64

// PDRBucketCapacity provisions every live hash key and bounded replacement
// headroom. ruleMutex permits one publication transaction at a time; the PFCP
// rule limit bounds it to 64 hash buckets. Reserve another such batch for
// retiring versions, capped at the original full-key replacement reserve for
// small maps. Additional retired batches use the bounded capacity wait.
func PDRBucketCapacity(keysPerMap uint32) (uint32, error) {
	live := 2 * uint64(keysPerMap)
	reserve := min(live, uint64(2*MaxRulesPerSession))
	total := live + reserve + 1 // Slot zero is never published.
	if keysPerMap == 0 || total > math.MaxUint32 {
		return 0, fmt.Errorf("invalid PDR map capacity %d", keysPerMap)
	}
	return uint32(total), nil
}

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
	id, err := b.nextRuleID(b.bucketIDs, &b.bucketMutex, &tx.capacityDeadline)
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
