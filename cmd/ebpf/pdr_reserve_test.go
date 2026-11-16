//go:build linux

package ebpf

import (
	"errors"
	"net"
	"sync"
	"testing"
)

func TestPDRReserveCoversLargestTransactionAndRetirementBatch(t *testing.T) {
	b := NewBpfObjects()
	b.SetPdrMapSize(128)
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	info, err := b.PdrBuckets.Info()
	if err != nil {
		t.Fatal(err)
	}
	// Two full key maps, one 64-key transaction and one 64-version grace batch.
	if info.MaxEntries != 385 {
		t.Fatalf("reserve is not bounded by transaction fanout: %d slots", info.MaxEntries)
	}
	write := func(owner uint64, far uint32) error {
		tx, err := b.BeginRuleTransaction(owner)
		if err != nil {
			return err
		}
		for id := uint32(1); id <= 64; id++ {
			pdr := PdrInfo{SessionID: owner, PdrID: id, FarId: far}
			if id <= 32 {
				err = tx.PutPdrUplink(uint32(owner-1)*32+id, pdr)
			} else {
				err = tx.PutPdrDownlink(net.IP{198, 51, byte(owner), byte(id)}, pdr)
			}
			if err != nil {
				return errors.Join(err, tx.Rollback())
			}
		}
		if err := tx.Commit(); err != nil {
			return errors.Join(err, tx.Rollback())
		}
		return nil
	}
	for owner := uint64(1); owner <= 4; owner++ {
		if err := write(owner, 1); err != nil {
			t.Fatal(err)
		}
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	signal := sync.OnceFunc(func() { close(entered) })
	t.Cleanup(unblock)
	original := b.grace.synchronize
	b.grace.synchronize = func() error { signal(); <-resume; return original() }
	if err := write(1, 2); err != nil {
		t.Fatal("first full transaction", err)
	}
	<-entered
	if err := write(2, 2); err != nil {
		t.Fatal("transaction could not overlap one full retirement batch", err)
	}
	if err := write(3, 2); !errors.Is(err, ErrRuleCapacity) {
		t.Fatal("stalled readers did not apply bounded backpressure", err)
	}
	var old IpEntrypointPdrInfo
	if err := b.LookupUplinkPDR(65, &old); err != nil || old.Entries[0].Pdr.FarId != 1 {
		t.Fatal("failed transaction changed the original version", err)
	}
	unblock()
	if err := <-b.graceBarrierForTest(); err != nil {
		t.Fatal(err)
	}
	if err := write(3, 2); err != nil {
		t.Fatal("retirement did not restore full-transaction capacity", err)
	}
	if err := <-b.graceBarrierForTest(); err != nil {
		t.Fatal(err)
	}
	b.grace.synchronize = original
}
