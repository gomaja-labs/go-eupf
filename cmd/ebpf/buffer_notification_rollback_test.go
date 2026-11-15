//go:build linux

package ebpf

import (
	"net"
	"testing"
)

func TestBufferNotificationResetRollbackPreservesConcurrentObservations(t *testing.T) {
	for _, readFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending-old-notice", true: "already-reported"}[readFirst], func(t *testing.T) {
			b := loadBufferContinuationDatapath(t)
			if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
				t.Fatal(err)
			}
			if err := b.UpdateFar(3, FarInfo{Action: 12, BufferSessionID: 42, BufferCookie: 7}); err != nil {
				t.Fatal(err)
			}
			if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3, QerIDs: []uint32{1}, NRFlag: true}); err != nil {
				t.Fatal(err)
			}
			send := func(qfi uint8, id uint16) {
				t.Helper()
				putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: qfi, QfiPresent: 1})
				if action, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 2, id)); err != nil || action != 1 {
					t.Fatalf("admit: %d %v", action, err)
				}
			}
			send(5, 100)
			var initial bufferFar
			if err := b.BufferStates.Lookup(bufferKey{SessionID: 42}, &initial); err != nil {
				t.Fatal(err)
			}
			oldTime := initial.NoticeTime[5]
			if readFirst {
				notice, present, err := b.ReadBufferNotice(42, 7, 0)
				if err != nil || !present {
					t.Fatalf("first notice: %+v %t %v", notice, present, err)
				}
				oldTime = notice.ReceivedNS
			}
			controller, err := b.BeginRuleTransaction(42)
			if err != nil {
				t.Fatal(err)
			}
			tx := controller.(*ruleTransaction)
			defer func() {
				if err := tx.Rollback(); err != nil {
					t.Error(err)
				}
			}()
			if err := tx.JournalBufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 10}); err != nil {
				t.Fatal(err)
			}
			send(5, 101)
			send(9, 102)
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			want := []uint8{5, 9}
			if readFirst {
				want = []uint8{9}
			}
			for _, qfi := range want {
				notice, present, err := b.ReadBufferNotice(42, 7, 0)
				if err != nil || !present || notice.QFI != qfi || notice.PDRID != 9 {
					t.Fatalf("rollback notice QFI=%d: %+v %t %v", qfi, notice, present, err)
				}
				if qfi == 5 && oldTime != 0 && notice.ReceivedNS != oldTime {
					t.Fatal("old notice timestamp replaced")
				}
			}
			if _, present, err := b.ReadBufferNotice(42, 7, 0); err != nil || present {
				t.Fatalf("rollback duplicated an old notification: %t %v", present, err)
			}
			state, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
			if err != nil || state.Produced != 3 || state.Outstanding != 3 {
				t.Fatalf("reset changed packet credits: %+v %v", state, err)
			}
		})
	}
}
