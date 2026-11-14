//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
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
	// Buffer anchors synchronize only a session's admitted packets. They are
	// not a publication gate; ordinary FORW rules have no buffering reference.
	// TS 29.244 V20.1.0 clauses 5.2.3.1 and 5.2.4.2.
	// PDR index locks are taken by kernel BPF_F_LOCK map updates, never by
	// packet instructions; the helper scan below preserves that distinction.
	kernelUpdateLocks := map[string]bool{"pdr_map_downlink_ip4": true, "pdr_map_teid_ip4": true}
	for name, mapSpec := range spec.Maps {
		if mapSpec.Value == nil {
			continue
		}
		value, ok := btf.UnderlyingType(mapSpec.Value).(*btf.Struct)
		if !ok {
			continue
		}
		for _, member := range value.Members {
			lock, ok := btf.UnderlyingType(member.Type).(*btf.Struct)
			if ok && lock.Name == "bpf_spin_lock" && name != "buffer_anchors" && name != "buffer_pool" && !kernelUpdateLocks[name] {
				t.Fatalf("shared packet gate in map %s", name)
			}
		}
	}
	allowed := map[string]bool{"buffer_admit": true, "upf_buffer_admission_func": true, "upf_buffer_control_func": true}
	for name, program := range spec.Programs {
		function := name
		for _, ins := range program.Instructions {
			if symbol := ins.Symbol(); symbol != "" {
				function = symbol
			}
			if ins.IsBuiltinCall() && (ins.Constant == int64(asm.FnSpinLock) || ins.Constant == int64(asm.FnSpinUnlock)) && !allowed[function] {
				t.Fatalf("rule consistency takes a BPF spin lock in %s", function)
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
		if err := pdrLookupTest(b, b.PdrMapTeidIp4)(key, &got); err != nil || got.Count != 4 {
			t.Fatalf("key=%d count=%d error=%v", key, got.Count, err)
		}
	}
}

func TestRuleTransactionPublishesIPv4DownlinkKey(t *testing.T) {
	b := loadDatapath(t)
	for _, ip := range []net.IP{{203, 0, 113, 17}, net.ParseIP("203.0.113.17")} {
		tx, err := b.BeginRuleTransaction(77)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() { _ = tx.Rollback() }()
			if err := tx.PutPdrDownlink(ip, PdrInfo{SessionID: 77, PdrID: 1, FarId: 1}); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}()
	}
	var value IpEntrypointPdrInfo
	if err := pdrLookupTest(b, b.PdrMapDownlinkIp4)([4]byte{203, 0, 113, 17}, &value); err != nil || value.Count != 1 || value.SessionId != 77 {
		t.Fatalf("published IPv4 bucket: %+v error=%v", value, err)
	}
	tx, err := b.BeginRuleTransaction(77)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.DeletePdrDownlink(net.ParseIP("203.0.113.17"), 77, 1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := pdrLookupTest(b, b.PdrMapDownlinkIp4)([4]byte{203, 0, 113, 17}, &value); !isKeyAbsent(err) {
		t.Fatalf("IPv4 key was not removed: %v", err)
	}
}

func TestRuleSynchronizationRequiresLoadedMaps(t *testing.T) {
	b := NewBpfObjects()
	if err := b.SynchronizeRules(); err == nil {
		t.Fatal("unloaded synchronization succeeded")
	}
	b = loadDatapath(t)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.SynchronizeRules(); err == nil {
		t.Fatal("closed synchronization succeeded")
	}
}
