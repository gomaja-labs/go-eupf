package service

import (
	"errors"
	"fmt"
	"math/bits"
	"testing"
	"time"
)

func TestAutomaticTEIDsSeparateRestartGenerations(t *testing.T) {
	for _, size := range []uint32{1, 3, 65535, MaxResourcePoolSize} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			start := time.Unix(1800000000, 0)
			old, err := newResourceManagerAt("", size, start)
			if err != nil {
				t.Fatal(err)
			}
			next, err := newResourceManagerAt("", size, start.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			oldIDs := make(map[uint32]bool, size)
			for i := uint32(1); i <= size; i++ {
				id, err := old.FTEIDM.AllocateTEID(1, i)
				if err != nil || id <= size {
					t.Fatalf("old allocation %d: %d %v (must exclude pre-upgrade range)", i, id, err)
				}
				oldIDs[id] = true
			}
			for i := uint32(1); i <= size; i++ {
				id, err := next.FTEIDM.AllocateTEID(1, i)
				if err != nil || oldIDs[id] || id <= size {
					t.Fatalf("restart allocation %d: %d %v", i, id, err)
				}
			}
		})
	}
}

func TestTEIDGenerationPeriodAndClockSteps(t *testing.T) {
	for _, size := range []uint32{1, 3, 65535, MaxResourcePoolSize} {
		period := (uint64(1) << (32 - bits.Len32(size))) - 1
		start := time.Unix(int64(period), 0)
		old, _ := newResourceManagerAt("", size, start)
		first, _ := old.FTEIDM.AllocateTEID(1, 1)
		for _, delta := range []int64{-int64(period), -1, 0, 1, int64(period)} {
			next, _ := newResourceManagerAt("", size, start.Add(time.Duration(delta)*time.Second))
			id, err := next.FTEIDM.AllocateTEID(1, 1)
			if err != nil || (id == first) != (delta%int64(period) == 0) {
				t.Fatalf("size %d step %d: %d vs %d (%v)", size, delta, id, first, err)
			}
		}
	}
}

func TestExplicitTEIDsOnlyOccupyTheirGeneration(t *testing.T) {
	old, _ := newResourceManagerAt("", 3, time.Unix(1800000000, 0))
	next, _ := newResourceManagerAt("", 3, time.Unix(1800000001, 0))
	previous, _ := old.FTEIDM.AllocateTEID(1, 1)
	current, _ := next.FTEIDM.AllocateTEID(1, 1)
	next.FTEIDM.ReleaseTEID(1)
	if err := next.FTEIDM.ReserveTEID(2, 1, previous); err != nil {
		t.Fatal(err)
	}
	if err := next.FTEIDM.ReserveTEID(3, 1, previous); !errors.Is(err, ErrResourceCollision) {
		t.Fatal("lost predecessor collision", err)
	}
	if err := next.FTEIDM.ReserveTEID(2, 2, previous); err != nil {
		t.Fatal("CHOOSE ID sharing", err)
	}
	if err := next.FTEIDM.ReserveTEID(4, 1, current); err != nil {
		t.Fatal(err)
	}
	for i := uint32(1); i <= 2; i++ {
		id, err := next.FTEIDM.AllocateTEID(5, i)
		if err != nil || id == current || id == previous {
			t.Fatal("generation reservation", id, err)
		}
	}
	if _, err := next.FTEIDM.AllocateTEID(5, 3); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("pool did not exhaust", err)
	}
	next.FTEIDM.ReleaseTEID(4)
	if id, err := next.FTEIDM.AllocateTEID(6, 1); err != nil || id != current {
		t.Fatal("FIFO reuse", id, err)
	}
	if err := next.FTEIDM.ReserveTEID(7, 1, 0); err == nil {
		t.Fatal("accepted zero")
	}
}

func TestAutomaticTEIDAllocationIgnoresIPv4RestorationPeriod(t *testing.T) {
	manager, _ := NewResourceManager("192.0.2.0/30", 1)
	manager.HoldAutomaticIPv4Until(time.Now().Add(time.Hour))
	if id, err := manager.FTEIDM.AllocateTEID(1, 1); err != nil || id == 0 {
		t.Fatal("TEID allocation held", id, err)
	}
	if _, err := manager.IPAM.AllocateIP(1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("IPv4 hold bypassed", err)
	}
	manager.HoldAutomaticIPv4Until(time.Now())
	if _, err := manager.IPAM.AllocateIP(1); err != nil {
		t.Fatal("expired or zero period still holds IPv4", err)
	}
}

func TestAutomaticTEIDsExcludeLegacyRangeAtGenerationWrap(t *testing.T) {
	for _, size := range []uint32{1, 3, 65535, MaxResourcePoolSize} {
		period := (uint64(1) << (32 - bits.Len32(size))) - 1
		for _, second := range []int64{0, int64(period) - 1, int64(period)} {
			manager, _ := newResourceManagerAt("", size, time.Unix(second, 0))
			id, err := manager.FTEIDM.AllocateTEID(1, 1)
			if err != nil || id <= size {
				t.Fatalf("size %d at %d allocated legacy TEID %d: %v", size, second, id, err)
			}
		}
	}
}

func TestForeignTEIDReservationsLeaveAutomaticIndicesFree(t *testing.T) {
	old, _ := newResourceManagerAt("", 3, time.Unix(1800000000, 0))
	predecessor, _ := old.FTEIDM.AllocateTEID(1, 1)
	for _, foreign := range []uint32{predecessor, 1, ^uint32(0)} {
		manager, _ := newResourceManagerAt("", 3, time.Unix(1800000001, 0))
		if err := manager.FTEIDM.ReserveTEID(1, 1, foreign); err != nil {
			t.Fatal(err)
		}
		for i := uint32(1); i <= 3; i++ {
			id, err := manager.FTEIDM.AllocateTEID(2, i)
			if err != nil || id != manager.FTEIDM.generationBase+i {
				t.Fatalf("foreign %d blocks index %d: %d %v", foreign, i, id, err)
			}
		}
		manager.FTEIDM.ReleaseTEID(1)
		if _, err := manager.FTEIDM.AllocateTEID(3, 1); !errors.Is(err, ErrResourceExhausted) {
			t.Fatal("foreign release freed a current lease", foreign, err)
		}
	}
}
