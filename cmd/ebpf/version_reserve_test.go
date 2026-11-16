//go:build linux

package ebpf

import (
	"errors"
	"testing"
)

func TestRuleVersionPoolsReserveBeyondConfiguredLiveCapacity(t *testing.T) {
	if err := IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	b := NewBpfObjects()
	b.SetFarMapSize(4)
	b.SetQerMapSize(4)
	b.SetUrrMapSize(4)
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, m := range []struct {
		name string
		info func() (uint32, error)
		want uint32
	}{
		{"FAR", func() (uint32, error) {
			v, e := b.FarMap.Info()
			if e != nil {
				return 0, e
			}
			return v.MaxEntries, nil
		}, 9},
		{"QER", func() (uint32, error) {
			v, e := b.QerMap.Info()
			if e != nil {
				return 0, e
			}
			return v.MaxEntries, nil
		}, 13},
		{"URR", func() (uint32, error) {
			v, e := b.UrrMap.Info()
			if e != nil {
				return 0, e
			}
			return v.MaxEntries, nil
		}, 9},
	} {
		n, err := m.info()
		if err != nil || n != m.want {
			t.Fatalf("%s slots=%d want %d: %v", m.name, n, m.want, err)
		}
	}
	for _, kind := range []string{"FAR", "QER", "URR"} {
		t.Run(kind, func(t *testing.T) {
			add := func(tx RuleTransaction) (uint32, error) {
				switch kind {
				case "FAR":
					return tx.NewFar(FarInfo{Action: 1})
				case "QER":
					return tx.NewQer(QerInfo{})
				default:
					return tx.NewUrr(UrrInfo{})
				}
			}
			remove := func(tx RuleTransaction, id uint32) error {
				switch kind {
				case "FAR":
					return tx.DeleteFar(id)
				case "QER":
					return tx.DeleteQer(id)
				default:
					_, err := tx.DeleteUrr(id)
					return err
				}
			}
			ids := make([]uint32, 4)
			for i := range ids {
				tx, err := b.BeginRuleTransaction(uint64(i + 1))
				if err != nil {
					t.Fatal(err)
				}
				ids[i], err = add(tx)
				if err == nil {
					err = tx.Commit()
				}
				if err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			}
			tx, err := b.BeginRuleTransaction(5)
			if err != nil {
				t.Fatal(err)
			}
			_, err = add(tx)
			if err == nil {
				err = tx.Commit()
			}
			_ = tx.Rollback()
			if !errors.Is(err, ErrRuleCapacity) {
				t.Fatalf("reserve was admitted as extra live %s: %v", kind, err)
			}
			for i, id := range ids {
				tx, err := b.BeginRuleTransaction(uint64(i + 1))
				if err != nil {
					t.Fatal(err)
				}
				_, err = add(tx)
				if err == nil {
					err = remove(tx, id)
				}
				if err == nil {
					err = tx.Commit()
				}
				if err != nil {
					_ = tx.Rollback()
					t.Fatalf("full live %s replacement: %v", kind, err)
				}
			}
			if err := b.SynchronizeRules(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFullQERPoolKeepsStablePolicerAnchorsAcrossReplacements(t *testing.T) {
	if err := IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	b := NewBpfObjects()
	b.SetQerMapSize(4)
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	}()
	current, anchor := make([]uint32, 4), make([]uint32, 4)
	for i := range current {
		id, err := b.NewQer(QerInfo{})
		if err != nil {
			t.Fatal(err)
		}
		current[i], anchor[i] = id, id
	}
	for round := range 4 {
		for i, old := range current {
			tx, err := b.BeginRuleTransaction(uint64(i + 1))
			if err != nil {
				t.Fatal(err)
			}
			next, err := tx.NewQer(QerInfo{PolicerID: anchor[i]})
			if err == nil {
				err = tx.RetireQer(old)
			}
			if err == nil {
				err = tx.Commit()
			}
			if err != nil {
				_ = tx.Rollback()
				t.Fatalf("round %d QER %d: %v", round, i, err)
			}
			current[i] = next
		}
	}
	if err := b.SynchronizeRules(); err != nil {
		t.Fatal(err)
	}
}
