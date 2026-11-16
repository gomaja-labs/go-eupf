//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestUnpublishedPDRMemoryDoesNotChangeReaders(t *testing.T) {
	b := loadDatapath(t)
	memory, err := b.PdrBuckets.Memory()
	if err != nil {
		t.Fatal(err)
	}
	if memory.ReadOnly() {
		t.Fatal("bucket memory is read-only")
	}
	info, err := b.PdrBuckets.Info()
	if err != nil {
		t.Fatal(err)
	}
	size := uint32(unsafe.Sizeof(IpEntrypointPdrBucket{}))
	if size != info.ValueSize || size%8 != 0 {
		t.Fatal("Go and mapped-array strides differ", size, info.ValueSize)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	before, _ := runDatapath(t, b, packet)
	slot := info.MaxEntries - 1
	raw := make([]byte, size)
	binary.NativeEndian.PutUint32(raw, 10)
	if _, err := memory.WriteAt(raw, int64(slot)*int64(size)); err != nil {
		t.Fatal(err)
	}
	after, _ := runDatapath(t, b, packet)
	if before != after {
		t.Fatal("an unreachable bucket changed a reader")
	}
	var got IpEntrypointPdrBucket
	if err := b.PdrBuckets.Lookup(slot, &got); err != nil || got.Key != 10 {
		t.Fatal("mapped write did not reach kernel array", got.Key, err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, FarId: 2, OuterHeaderRemovalPresent: true}); err != nil {
		t.Fatal(err)
	}
	action, _ := runDatapath(t, b, packet)
	var published IpEntrypointPdrInfo
	if err := b.LookupUplinkPDR(10, &published); err != nil || published.Count != 1 || published.Entries[0].Pdr.FarId != 2 {
		t.Fatal("completed bucket was not published", published.Count, err)
	}
	if action != 1 {
		t.Fatal("descriptor did not publish the completed bucket", action)
	}
}

func TestFreshFARMemoryWritesCompleteConfiguration(t *testing.T) {
	b := loadDatapath(t)
	tx, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	id, err := tx.NewFar(FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 77, RemoteIP: 44, TransportLevelMarking: 0xabfc})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	info, err := b.GetFar(id)
	if err != nil || info.Action != 2 || info.OuterHeaderCreation != 1 || info.Teid != 77 || info.RemoteIP != 44 || info.TransportLevelMarking != 0xabfc {
		t.Fatal("mapped FAR differs from complete configuration", info, err)
	}
}
func TestSharedRuleMappingsAreReleasedOnClose(t *testing.T) {
	b := loadDatapath(t)
	mappings := [][]byte{b.bucketMemory.data, b.farMemory.data}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	for _, data := range mappings {
		if err := unix.Munmap(data); !errors.Is(err, unix.EINVAL) {
			t.Fatal("Close left a rule mapping owned by the process", err)
		}
	}
}
