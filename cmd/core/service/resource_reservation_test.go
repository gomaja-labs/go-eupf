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
func TestReservationViewDoesNotMutateLivePools(t *testing.T) {
	m, _ := NewResourceManager("192.0.2.0/30", 1)
	view := m.Clone()
	_, _ = view.IPAM.AllocateIP(10)
	_, _ = view.FTEIDM.AllocateTEID(10, 1)
	if len(m.IPAM.busyIPs) != 0 || len(m.FTEIDM.busyTEIDs) != 0 {
		t.Fatal("draft reservations escaped")
	}
	m.CommitReservations(view)
	if _, err := m.FTEIDM.AllocateTEID(20, 1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal(err)
	}
	m.IPAM.ReleaseIP(10)
	m.FTEIDM.ReleaseTEID(10)
	m.IPAM.ReleaseIP(10)
	m.FTEIDM.ReleaseTEID(10)
	if len(m.FTEIDM.freeTEIDs) != 1 {
		t.Fatal("double release duplicated lease")
	}
}
