//go:build linux

package ebpf

import (
	"encoding/binary"
	"testing"
)

func TestSessionActivityCoalescesPacketsBetweenPolls(t *testing.T) {
	b := loadDatapath(t)
	slot, err := b.NewSessionActivity()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, ActivitySlot: slot, OuterHeaderRemovalPresent: true}); err != nil {
		t.Fatal(err)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	for range 8 {
		if action, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil || action != 1 {
			t.Fatal("expected matched DROP", action, err)
		}
	}
	if value, err := b.sessionActivityValue(slot); err != nil || value != 1 {
		t.Fatalf("activity did not coalesce: value=%d error=%v", value, err)
	}
	if active, err := b.ConsumeSessionActivity(slot); err != nil || !active {
		t.Fatal("poll did not consume activity", active, err)
	}
	if active, err := b.ConsumeSessionActivity(slot); err != nil || active {
		t.Fatal("poll repeated activity without a packet", active, err)
	}
	if action, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil || action != 1 {
		t.Fatal(action, err)
	}
	if active, err := b.ConsumeSessionActivity(slot); err != nil || !active {
		t.Fatal("next interval lost activity", active, err)
	}
}

func TestSessionActivityLateStoresAndReuse(t *testing.T) {
	b := loadDatapath(t)
	slot, err := b.NewSessionActivity()
	if err != nil {
		t.Fatal(err)
	}
	store := func() {
		t.Helper()
		var value [8]byte
		binary.NativeEndian.PutUint64(value[:], 1)
		if _, err := b.activityMemory.WriteAt(value[:], int64(slot)*8); err != nil {
			t.Fatal(err)
		}
	}
	if active, err := b.ConsumeSessionActivity(slot); err != nil || active {
		t.Fatal("new session inherited activity", active, err)
	}
	// A packet that read clear before the poll may complete its store afterwards.
	// The next poll must see it, even when another newer packet has also stored.
	store()
	store()
	if active, err := b.ConsumeSessionActivity(slot); err != nil || !active {
		t.Fatal("late store hid newer activity", active, err)
	}
	store()
	b.ReleaseSessionActivity(slot)
	reused, err := b.NewSessionActivity()
	if err != nil || reused != slot {
		t.Fatal("slot reuse", reused, err)
	}
	if active, err := b.ConsumeSessionActivity(reused); err != nil || active {
		t.Fatal("new lifetime inherited predecessor activity", active, err)
	}
	if active, err := b.ConsumeSessionActivity(0); err == nil || active {
		t.Fatal("slot zero was monitored")
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	if _, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil {
		t.Fatal(err)
	}
	var zero uint64
	if err := b.SessionActivity.Lookup(uint32(0), &zero); err != nil || zero != 0 {
		t.Fatal("unmonitored packet touched slot zero", zero, err)
	}
}
