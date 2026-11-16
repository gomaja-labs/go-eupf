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
	// Reclamation returns the identifier without clearing immutable bytes.
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := b.SynchronizeRules(); err != nil {
		t.Fatal(err)
	}
	var retained IpEntrypointFarInfo
	if err := b.FarMap.Lookup(id, &retained); err != nil || retained.Action != 2 {
		t.Fatal("retirement rewrote immutable configuration", retained, err)
	}
	if next, err := b.GetNextFAR(); err != nil || next != id {
		t.Fatalf("retired slot not reclaimed: %d %v", next, err)
	}
}
