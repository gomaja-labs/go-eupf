//go:build linux

package ebpf

import "testing"

func TestRetiredFARNeedsNoConfigurationClear(t *testing.T) {
	b := loadDatapath(t)
	id, err := b.NewFar(FarInfo{Action: 2})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := b.BeginRuleTransaction(100)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.DeleteFar(id); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	// There are no remaining readers after detachment and grace. Reclamation
	// can return the slot without a configuration write to this immutable map.
	if err := b.FarMap.Freeze(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := b.SynchronizeRules(); err != nil {
		t.Fatal(err)
	}
	if next, err := b.GetNextFAR(); err != nil || next != id {
		t.Fatalf("retired slot not reclaimed: %d %v", next, err)
	}
}
