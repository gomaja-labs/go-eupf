//go:build linux

package ebpf

import (
	"errors"
	"net"
	"testing"
)

func TestBufferRollbackAfterOneOfTwoPDRKeysPublishes(t *testing.T) {
	b := loadBufferContinuationDatapath(t)
	if err := b.CreateBufferAnchor(42, 4, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateFar(3, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7}); err != nil {
		t.Fatal(err)
	}
	old := PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}
	for _, last := range []byte{2, 3} {
		if err := b.PutPdrDownlink(net.IP{198, 51, 100, last}, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 2, 100)); err != nil {
		t.Fatal(err)
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
	if err := tx.JournalBufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 1, Mode: BufferDrain}); err != nil {
		t.Fatal(err)
	}
	changed := old
	changed.FarId = 2
	for _, last := range []byte{2, 3} {
		if err := tx.PutPdrDownlink(net.IP{198, 51, 100, last}, changed); err != nil {
			t.Fatal(err)
		}
	}
	injected := errors.New("second PDR publication failed")
	partial := false
	tx.beforeWrite = func() error {
		var first, second IpEntrypointPdrInfo
		if err := pdrLookupTest(b, b.PdrMapDownlinkIp4)([4]byte{198, 51, 100, 2}, &first); err != nil {
			return err
		}
		if err := pdrLookupTest(b, b.PdrMapDownlinkIp4)([4]byte{198, 51, 100, 3}, &second); err != nil {
			return err
		}
		if first.Entries[0].Pdr.FarId == 2 && second.Entries[0].Pdr.FarId == 3 {
			partial = true
			// The other key still admits live data during a partial publication.
			if _, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 3, 101)); err != nil {
				return err
			}
			if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Sequence: 1, Downlink: true}); err != nil {
				return err
			}
			return injected
		}
		return nil
	}
	if err := tx.Commit(); !errors.Is(err, injected) || !partial {
		t.Fatalf("partial publication=%t error=%v", partial, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for _, last := range []byte{2, 3} {
		var got IpEntrypointPdrInfo
		if err := pdrLookupTest(b, b.PdrMapDownlinkIp4)([4]byte{198, 51, 100, last}, &got); err != nil || got.Entries[0].Pdr.FarId != 3 {
			t.Fatalf("PDR %d not restored: %+v %v", last, got, err)
		}
	}
	state, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
	if err != nil || state.Mode != BufferHold || state.Produced != 2 || state.Completed != 1 || state.Outstanding != 1 {
		t.Fatalf("rollback lost live credits: %+v %v", state, err)
	}
}
