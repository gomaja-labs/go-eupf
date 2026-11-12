package service

import (
	"errors"
	"net"
	"testing"
)

func TestExplicitResourcesCannotBeReallocated(t *testing.T) {
	m, err := NewResourceManager("192.0.2.0/30", 3)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("192.0.2.1")
	if err = m.IPAM.ReserveIP(100, ip); err != nil {
		t.Fatal(err)
	}
	if err = m.FTEIDM.ReserveTEID(100, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err = m.IPAM.ReserveIP(200, ip); !errors.Is(err, ErrResourceCollision) {
		t.Fatal(err)
	}
	if err = m.FTEIDM.ReserveTEID(200, 1, 1); !errors.Is(err, ErrResourceCollision) {
		t.Fatal(err)
	}
	got, err := m.IPAM.AllocateIP(200)
	if err != nil || got.Equal(ip) {
		t.Fatalf("allocated owned address %s: %v", got, err)
	}
	teid, err := m.FTEIDM.AllocateTEID(200, 1)
	if err != nil || teid == 1 {
		t.Fatalf("allocated owned TEID %d: %v", teid, err)
	}
}
func TestSharedTEIDReleasedOnlyAfterLastReference(t *testing.T) {
	m, _ := NewResourceManager("", 1)
	if err := m.FTEIDM.ReserveTEID(10, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.FTEIDM.ReserveTEID(10, 2, 1); err != nil {
		t.Fatal(err)
	}
	m.FTEIDM.ReleaseUnused(10, map[uint32]uint32{2: 1})
	if _, err := m.FTEIDM.AllocateTEID(20, 1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatalf("released shared TEID early: %v", err)
	}
	m.FTEIDM.ReleaseUnused(10, nil)
	got, err := m.FTEIDM.AllocateTEID(20, 1)
	if err != nil || got != 1 {
		t.Fatalf("did not recycle final reference: %d %v", got, err)
	}
}
func TestReservationJournalReservesBeforePublicationAndUndoesFailure(t *testing.T) {
	m, _ := NewResourceManager("192.0.2.0/30", 1)
	journal := m.BeginReservation(10)
	view := journal.View()
	_, _ = view.IPAM.AllocateIP(10)
	_, _ = view.FTEIDM.AllocateTEID(10, 1)
	if _, err := m.FTEIDM.AllocateTEID(20, 1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("uncommitted reservation was available to another endpoint")
	}
	reclaim := journal.Rollback()
	if _, err := m.FTEIDM.AllocateTEID(20, 1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("rollback released before grace")
	}
	if reclaim != nil {
		_ = reclaim()
	}
	if id, err := m.FTEIDM.AllocateTEID(20, 1); err != nil || id != 1 {
		t.Fatalf("rollback did not return reservation: %d %v", id, err)
	}
	if reclaim != nil {
		_ = reclaim()
	}
	if _, err := m.FTEIDM.AllocateTEID(30, 1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("late callback released a new lease")
	}
}

func TestRetiredLeaseCannotBeReattachedOrFreedByAnOldCallback(t *testing.T) {
	manager, _ := NewResourceManager("192.0.2.0/30", 1)
	if err := manager.FTEIDM.ReserveTEID(10, 1, 1); err != nil {
		t.Fatal(err)
	}
	journal := manager.BeginReservation(10)
	journal.View().FTEIDM.ReleaseTEID(10)
	old := journal.Commit()
	if err := manager.FTEIDM.ReserveTEID(10, 1, 1); !errors.Is(err, ErrResourceCollision) {
		t.Fatal("reattached a retiring TEID")
	}
	if err := manager.FTEIDM.ReserveTEID(20, 1, 1); !errors.Is(err, ErrResourceCollision) {
		t.Fatal("reused a retiring TEID")
	}
	if err := old(); err != nil {
		t.Fatal(err)
	}
	if err := manager.FTEIDM.ReserveTEID(10, 1, 1); err != nil {
		t.Fatal(err)
	}
	newer := manager.BeginReservation(10)
	newer.View().FTEIDM.ReleaseTEID(10)
	current := newer.Commit()
	if err := old(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FTEIDM.AllocateTEID(20, 1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("old callback freed a newer retired lease")
	}
	if err := current(); err != nil {
		t.Fatal(err)
	}
	if id, err := manager.FTEIDM.AllocateTEID(20, 1); err != nil || id != 1 {
		t.Fatalf("final reclamation: %d %v", id, err)
	}
}

func TestRetiredIPv6PrefixKeepsCollisionClaimUntilGrace(t *testing.T) {
	manager, _ := NewResourceManager("", 0)
	ip := net.ParseIP("2001:db8:17::1")
	mask := net.CIDRMask(64, 128)
	if err := manager.IPAM.ReserveIPv6Prefix(10, ip, mask); err != nil {
		t.Fatal(err)
	}
	journal := manager.BeginReservation(10)
	journal.View().IPAM.ReleaseIP(10)
	retire := journal.Commit()
	if err := manager.IPAM.ReserveIP(20, net.ParseIP("2001:db8:17::2")); !errors.Is(err, ErrResourceCollision) {
		t.Fatal("retired prefix lost its collision claim")
	}
	if err := manager.IPAM.ReserveIPv6Prefix(10, ip, mask); !errors.Is(err, ErrResourceCollision) {
		t.Fatal("reattached a retiring prefix")
	}
	if err := retire(); err != nil {
		t.Fatal(err)
	}
	if err := manager.IPAM.ReserveIP(20, net.ParseIP("2001:db8:17::2")); err != nil {
		t.Fatal(err)
	}
}
