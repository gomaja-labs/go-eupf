//go:build linux

package ebpf

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRuleJournalRestoresEveryFailureStep(t *testing.T) {
	for failure := 0; failure <= 5; failure++ {
		t.Run(string(rune('0'+failure)), func(t *testing.T) {
			b := loadDatapath(t)
			if _, err := b.GetNextFAR(); err != nil {
				t.Fatal(err)
			}
			if _, err := b.GetNextQER(); err != nil {
				t.Fatal(err)
			}
			if _, err := b.GetNextURR(); err != nil {
				t.Fatal(err)
			}
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
			if action, _ := runDatapath(t, b, packet); action == 1 {
				t.Fatalf("transaction blocked unchanged user plane: %d", action)
			}
			if err := b.UrrMap.Lookup(uint32(1), &urr); err != nil {
				t.Fatal(err)
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
				if applyErr = tx.publishPDRs(); applyErr != nil {
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
			if next, err := b.GetNextFAR(); err != nil || next != 2 {
				t.Fatalf("FAR allocator=%d %v", next, err)
			}
			if next, err := b.GetNextURR(); err != nil || next != 2 {
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

func TestFrozenPDRDeletionKeepsLiveSlot(t *testing.T) {
	b := loadDatapath(t)
	id, err := b.NewFar(FarInfo{Action: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PdrMapTeidIp4.Freeze(); err != nil {
		t.Fatal(err)
	}
	tx, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.DeleteFar(id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("frozen PDR accepted detachment")
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

func TestRetainedURRResetIsJournalled(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.UrrMap.Put, uint32(1), &IpEntrypointUrrInfo{Ul: 99, Dl: 77})
	controller, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = controller.Rollback() }()
	if err := controller.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := controller.ResetUrr(1); err != nil {
		t.Fatal(err)
	}
	zero, err := b.GetUrr(1)
	if err != nil || zero.UplinkVolume != 0 || zero.DownlinkVolume != 0 {
		t.Fatalf("reset=%+v %v", zero, err)
	}
	if err := controller.Rollback(); err != nil {
		t.Fatal(err)
	}
	restored, err := b.GetUrr(1)
	if err != nil || restored.UplinkVolume != 99 || restored.DownlinkVolume != 77 {
		t.Fatalf("rollback=%+v %v", restored, err)
	}
	var pdr IpEntrypointPdrInfo
	if err := b.PdrMapTeidIp4.Lookup(uint32(10), &pdr); err != nil || pdr.Count != 1 {
		t.Fatal("reset rollback lost PDR")
	}
}

func TestConcurrentOldPacketsCannotChargeReusedURR(t *testing.T) {
	b := loadDatapath(t)
	if id, err := b.GetNextURR(); err != nil || id != 1 {
		t.Fatalf("reserve old URR: %d %v", id, err)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	epoch := make(chan struct{})
	var stop sync.Once
	var ready, workers sync.WaitGroup
	failures := make(chan error, 4)
	ready.Add(4)
	for range 4 {
		workers.Go(func() {
			if _, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil {
				failures <- err
				ready.Done()
				return
			}
			ready.Done()
			for {
				select {
				case <-epoch:
					for range 100 {
						if _, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil {
							failures <- err
							return
						}
					}
					return
				default:
					if _, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil {
						failures <- err
						return
					}
				}
			}
		})
	}
	t.Cleanup(func() { stop.Do(func() { close(epoch) }); workers.Wait() })
	ready.Wait()
	controller, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = controller.Rollback() }()
	final, err := controller.DeleteUrr(1)
	if err != nil || final.UplinkVolume == 0 {
		t.Fatalf("final=%+v %v", final, err)
	}
	if err := controller.Commit(); err != nil {
		t.Fatal(err)
	}
	reused, err := b.BeginRuleTransaction(9)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reused.Rollback() }()
	id, err := reused.NewUrr(UrrInfo{})
	if err != nil || id != 1 {
		t.Fatalf("reuse=%d %v", id, err)
	}
	if err := reused.Commit(); err != nil {
		t.Fatal(err)
	}
	stop.Do(func() { close(epoch) })
	workers.Wait()
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
	current, err := b.GetUrr(1)
	if err != nil || current.UplinkVolume != 0 || current.DownlinkVolume != 0 {
		t.Fatalf("old packets charged new session: %+v %v", current, err)
	}
}

func TestDetachedURRFromEarlierTransactionStillWaits(t *testing.T) {
	b := loadDatapath(t)
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 2, FarId: 1}); err != nil {
		t.Fatal(err)
	}
	first, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	var waits atomic.Int32
	kernelWait := b.grace.synchronize
	b.grace.synchronize = func() error { waits.Add(1); return kernelWait() }
	next, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = next.Rollback() }()
	if _, err := next.DeleteUrr(1); err != nil {
		t.Fatal(err)
	}
	if waits.Load() == 0 {
		t.Fatal("final usage skipped grace for a rule detached by an earlier transaction")
	}
	if err := next.Commit(); err != nil {
		t.Fatal(err)
	}
}
