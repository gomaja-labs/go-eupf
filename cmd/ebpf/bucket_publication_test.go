//go:build linux

package ebpf

import (
	"net"
	"sync"
	"testing"
	"time"

	cilium "github.com/cilium/ebpf"
	"github.com/gopacket/gopacket/layers"
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

func TestPDRImageRollbackRetainsOtherEntries(t *testing.T) {
	b := loadDatapath(t)
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, FarId: 2}); err != nil {
		t.Fatal(err)
	}
	controller, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	tx := controller.(*ruleTransaction)
	if err := tx.DeletePdrUplink(10, 0, 2); err != nil {
		t.Fatal(err)
	}
	if err := tx.publishPDRs(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 3, FarId: 2}); err != nil {
		t.Fatal(err)
	}
	var bucket IpEntrypointPdrInfo
	if err := b.LookupUplinkPDR(10, &bucket); err != nil {
		t.Fatal(err)
	}
	if bucket.Count != 3 {
		t.Fatalf("rollback left a stale publication image: count=%d", bucket.Count)
	}
	want := map[uint32]uint32{1: 1, 2: 2, 3: 2}
	for _, entry := range bucket.Entries[:bucket.Count] {
		far, ok := want[entry.PdrId]
		if !ok || entry.Pdr.FarId != far {
			t.Fatalf("a draft changed its rollback image: PDR %d FAR %d", entry.PdrId, entry.Pdr.FarId)
		}
		delete(want, entry.PdrId)
	}
}

func TestRollbackKeepsNewConfigurationsUntilGrace(t *testing.T) {
	b := loadDatapath(t)
	for range 3 {
		if _, err := b.GetNextFAR(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.GetNextQER(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GetNextURR(); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(unblock)
	signal := sync.OnceFunc(func() { close(entered) })
	original := b.grace.synchronize
	b.grace.synchronize = func() error { signal(); <-resume; return original() }
	controller, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	tx := controller.(*ruleTransaction)
	far, err := tx.NewFar(FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: 1234})
	if err != nil {
		t.Fatal(err)
	}
	qer, err := tx.NewQer(QerInfo{Qfi: 9, MaxBitrateUL: 12345})
	if err != nil {
		t.Fatal(err)
	}
	urr, err := tx.NewUrr(UrrInfo{UplinkVolume: 42})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PutPdrUplink(10, PdrInfo{PdrID: 1, FarId: far, QerIDs: []uint32{qer}, UrrIDs: []uint32{urr}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.publishPDRs(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("rollback did not wait for old readers")
	}
	var fv IpEntrypointFarInfo
	var qv IpEntrypointQerInfo
	if err := b.FarMap.Lookup(far, &fv); err != nil {
		t.Fatal(err)
	}
	if err := b.QerMap.Lookup(qer, &qv); err != nil {
		t.Fatal(err)
	}
	if fv.Action != 2 || fv.Teid != 200 || fv.Remoteip != 1234 {
		t.Errorf("rollback overwrote a FAR still held by readers: %+v", fv)
	}
	if qv.Qfi != 9 || qv.UlMaximumBitrate != 12345 {
		t.Errorf("rollback overwrote a QER still held by readers: %+v", qv)
	}
	var uv IpEntrypointUrrInfo
	if err := b.UrrMap.Lookup(urr, &uv); err != nil {
		t.Fatal(err)
	}
	if uv.Ul != 42 {
		t.Errorf("rollback overwrote a URR before the grace: %+v", uv)
	}
	unblock()
	if err := b.SynchronizeRules(); err != nil {
		t.Fatal(err)
	}
	if err := b.FarMap.Lookup(far, &fv); err != nil {
		t.Fatal(err)
	}
	if err := b.QerMap.Lookup(qer, &qv); err != nil {
		t.Fatal(err)
	}
	if err := b.UrrMap.Lookup(urr, &uv); err != nil {
		t.Fatal(err)
	}
	if fv != (IpEntrypointFarInfo{}) || qv != (IpEntrypointQerInfo{}) || uv != (IpEntrypointUrrInfo{}) {
		t.Fatal("rollback leaked unreachable configuration")
	}
}

func TestConfigurationWritesRequireFreshSlots(t *testing.T) {
	b := loadDatapath(t)
	tx, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			t.Error(err)
		}
	}()
	if err := tx.UpdateFar(1, FarInfo{Action: 1}); err == nil {
		t.Error("overwrote a live FAR without replacement")
	}
	if err := tx.UpdateQer(1, QerInfo{GateStatusUL: 1}); err == nil {
		t.Error("overwrote a live QER without replacement")
	}
	id, err := tx.NewFar(FarInfo{Action: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.UpdateFar(id, FarInfo{Action: 1}); err == nil {
		t.Error("rewrote an initialized configuration version")
	}
}

func TestPDRImageRollbackPreservesNotificationState(t *testing.T) {
	b := loadDatapath(t)
	ip := net.ParseIP("2001:db8::2")
	info := PdrInfo{SessionID: 9, PdrID: 1, FarId: 3, NotifyFlag: true}
	if err := b.PutPdrDownlink(ip, info); err != nil {
		t.Fatal(err)
	}
	runDatapath(t, b, ethernetDatapath(t, layers.EthernetTypeIPv6, udpDatapath(t, true)))
	before, err := b.LookupDownlinkPDR(ip)
	if err != nil {
		t.Fatal(err)
	}
	if before.Entries[0].Notify != 2 {
		t.Fatal("packet did not consume the notification flag")
	}
	controller, err := b.BeginRuleTransaction(9)
	if err != nil {
		t.Fatal(err)
	}
	tx := controller.(*ruleTransaction)
	t.Cleanup(func() { _ = tx.Rollback() })
	info.FarId = 2
	if err := tx.PutPdrDownlink(ip, info); err != nil {
		t.Fatal(err)
	}
	if err := tx.publishPDRs(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	after, err := b.LookupDownlinkPDR(ip)
	if err != nil {
		t.Fatal(err)
	}
	if after.Entries[0].Notify != 2 {
		t.Fatal("rollback rearmed the consumed notification")
	}
}
