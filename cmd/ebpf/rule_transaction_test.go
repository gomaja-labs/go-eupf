//go:build linux

package ebpf

import (
	"errors"
	"reflect"
	"testing"
)

func TestRuleJournalRestoresEveryFailureStep(t *testing.T) {
	for failure := 0; failure <= 5; failure++ {
		t.Run(string(rune('0'+failure)), func(t *testing.T) {
			b := loadDatapath(t)
			putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{UlStart: 123, DlStart: 456})
			putDatapath(t, b.UrrMap.Put, uint32(1), &IpEntrypointUrrInfo{Ul: 1234, Dl: 5678})
			var pdr IpEntrypointPdrInfo
			var far IpEntrypointFarInfo
			var qer IpEntrypointQerInfo
			var urr IpEntrypointUrrInfo
			if err := b.PdrMapTeidIp4.Lookup(uint32(10), &pdr); err != nil {
				t.Fatal(err)
			}
			if err := b.FarMap.Lookup(uint32(1), &far); err != nil {
				t.Fatal(err)
			}
			if err := b.QerMap.Lookup(uint32(1), &qer); err != nil {
				t.Fatal(err)
			}
			if err := b.UrrMap.Lookup(uint32(1), &urr); err != nil {
				t.Fatal(err)
			}
			controller, err := b.BeginRuleTransaction(0)
			if err != nil {
				t.Fatal(err)
			}
			tx := controller.(*ruleTransaction)
			t.Cleanup(func() {
				if err := tx.Rollback(); err != nil {
					t.Error(err)
				}
			})
			packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
			if action, _ := runDatapath(t, b, packet); action != 1 {
				t.Fatalf("quiescent gate forwarded known user plane: %d", action)
			}
			step := 0
			injected := errors.New("injected map failure")
			tx.beforeWrite = func() error {
				current := step
				step++
				if current == failure {
					return injected
				}
				return nil
			}
			operations := []func() error{
				func() error { _, err := tx.NewFar(FarInfo{Action: 1}); return err },
				func() error { return tx.UpdateQer(1, QerInfo{Qfi: 7, MaxBitrateUL: 1000}) },
				func() error { _, err := tx.NewUrr(UrrInfo{}); return err },
				func() error { return tx.PutPdrUplink(11, PdrInfo{PdrID: 9, FarId: 1}) },
				func() error { return tx.DeletePdrUplink(10, 0, 1) },
			}
			var applyErr error
			for _, operation := range operations {
				if applyErr = operation(); applyErr != nil {
					break
				}
			}
			if failure < len(operations) && !errors.Is(applyErr, injected) {
				t.Fatalf("failure %d: %v", failure, applyErr)
			}
			if failure == len(operations) && applyErr != nil {
				t.Fatal(applyErr)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			assertMapValue(t, b.PdrMapTeidIp4.Lookup, uint32(10), pdr)
			assertMapValue(t, b.FarMap.Lookup, uint32(1), far)
			assertMapValue(t, b.QerMap.Lookup, uint32(1), qer)
			assertMapValue(t, b.UrrMap.Lookup, uint32(1), urr)
			var absent IpEntrypointPdrInfo
			if err := b.PdrMapTeidIp4.Lookup(uint32(11), &absent); !isKeyAbsent(err) {
				t.Fatalf("rollback retained a new key: %v", err)
			}
			if next, err := b.GetNextFAR(); err != nil || next != 1 {
				t.Fatalf("FAR allocator=%d %v", next, err)
			}
			if next, err := b.GetNextURR(); err != nil || next != 1 {
				t.Fatalf("URR allocator=%d %v", next, err)
			}
			if action, _ := runDatapath(t, b, packet); action == 1 {
				t.Fatal("rollback left the gate closed")
			}
		})
	}
}

func assertMapValue[T any](t *testing.T, lookup func(interface{}, interface{}) error, key interface{}, want T) {
	t.Helper()
	var got T
	if err := lookup(key, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("map value was not restored exactly: got=%+v want=%+v", got, want)
	}
}

func TestFrozenMapDeletionKeepsLiveSlot(t *testing.T) {
	b := loadDatapath(t)
	id, err := b.NewFar(FarInfo{Action: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.FarMap.Freeze(); err != nil {
		t.Fatal(err)
	}
	tx, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.DeleteFar(id); err == nil {
		t.Fatal("frozen FAR accepted deletion")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if next, err := b.GetNextFAR(); err != nil || next == id {
		t.Fatalf("live FAR slot reused: %d %v", next, err)
	}
	info, err := b.GetFar(id)
	if err != nil || info.Action != 2 {
		t.Fatalf("live FAR changed: %+v %v", info, err)
	}
}
