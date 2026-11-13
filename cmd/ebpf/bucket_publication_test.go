//go:build linux

package ebpf

import (
	"sync"
	"testing"
	"time"

	cilium "github.com/cilium/ebpf"
)

func pdrLookupTest(b *BpfObjects, m *cilium.Map) func(interface{}, interface{}) error {
	return func(key, value interface{}) error { return b.lookupPDR(m, key, value.(*IpEntrypointPdrInfo), true) }
}

func TestBucketSlotsRetireAfterReaders(t *testing.T) {
	b := loadDatapath(t)
	var first IpEntrypointPdrIndex
	if err := b.PdrMapTeidIp4.Lookup(uint32(10), &first); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	original := b.grace.synchronize
	b.grace.synchronize = func() error { close(entered); <-release; return original() }
	p := PdrInfo{PdrID: 1, FarId: 2}
	if err := b.PutPdrUplink(10, p); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("old bucket did not enter reclamation grace")
	}
	var next IpEntrypointPdrIndex
	if err := b.PdrMapTeidIp4.Lookup(uint32(10), &next); err != nil {
		t.Fatal(err)
	}
	var old IpEntrypointPdrBucket
	if err := b.PdrBuckets.Lookup(first.Slot, &old); err != nil {
		t.Fatal(err)
	}
	if next.Slot == first.Slot || old.Info.Entries[0].Pdr.FarId != 1 {
		t.Error("overwrote a published bucket before the grace")
	}
	b.bucketMutex.Lock()
	free := b.bucketIDs.bitmap.Contains(first.Slot)
	b.bucketMutex.Unlock()
	if free {
		t.Error("old bucket already reusable")
	}
	unblock()
	// Restore only after that barrier completes, with no concurrent writes.
	if err := <-b.graceBarrierForTest(); err != nil {
		t.Fatal(err)
	}
	b.grace.synchronize = original
	b.bucketMutex.Lock()
	free = b.bucketIDs.bitmap.Contains(first.Slot)
	b.bucketMutex.Unlock()
	if !free {
		t.Error("old bucket leaked after the grace")
	}
}
func (b *BpfObjects) graceBarrierForTest() <-chan error {
	done := make(chan error, 1)
	b.grace.enqueue(graceWork{graced: true, done: done})
	return done
}
