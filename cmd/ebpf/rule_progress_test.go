//go:build linux

package ebpf

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf/asm"
)

func TestRuleTransactionDoesNotBlockUnrelatedTraffic(t *testing.T) {
	b := loadDatapath(t)
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	expected, _, err := b.UpfIpEntrypointFunc.Test(packet)
	if err != nil || expected == 1 {
		t.Fatalf("before transaction: %d %v", expected, err)
	}
	tx, err := b.BeginRuleTransaction(999)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	done := make(chan error, 1)
	go func() {
		for range 1000 {
			action, _, e := b.UpfIpEntrypointFunc.Test(packet)
			if e != nil {
				done <- e
				return
			}
			if action != expected {
				done <- fmt.Errorf("transaction changed unrelated action from %d to %d", expected, action)
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("traffic stopped during transaction")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestRuleConsistencyHasNoSharedPacketGate(t *testing.T) {
	spec, err := LoadIpEntrypoint()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := spec.Maps["rule_gate"]; exists {
		t.Fatal("packet path still writes a shared rule gate")
	}
	for _, program := range spec.Programs {
		for _, ins := range program.Instructions {
			if ins.IsBuiltinCall() && (ins.Constant == int64(asm.FnSpinLock) || ins.Constant == int64(asm.FnSpinUnlock)) {
				t.Fatal("rule consistency still takes a BPF spin lock")
			}
		}
	}
}

func TestRuleTransactionUsesFinalBucketCapacity(t *testing.T) {
	b := loadDatapath(t)
	for id := uint32(2); id <= 4; id++ {
		if err := b.PutPdrUplink(10, PdrInfo{PdrID: id, FarId: 1}); err != nil {
			t.Fatal(err)
		}
	}
	for id := uint32(5); id <= 8; id++ {
		if err := b.PutPdrUplink(11, PdrInfo{PdrID: id, FarId: 1}); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	// Both final buckets have four rules; temporary construction needs five.
	if err := tx.PutPdrUplink(11, PdrInfo{PdrID: 1, FarId: 1}); err != nil {
		t.Fatalf("temporary capacity rejected valid final plan: %v", err)
	}
	if err := tx.PutPdrUplink(10, PdrInfo{PdrID: 5, FarId: 1}); err != nil {
		t.Fatal(err)
	}
	if err := tx.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := tx.DeletePdrUplink(11, 0, 5); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []uint32{10, 11} {
		var got IpEntrypointPdrInfo
		if err := b.PdrMapTeidIp4.Lookup(key, &got); err != nil || got.Count != 4 {
			t.Fatalf("key=%d count=%d error=%v", key, got.Count, err)
		}
	}
}
