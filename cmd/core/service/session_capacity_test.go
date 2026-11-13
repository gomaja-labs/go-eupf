package service

import (
	"errors"
	"sync"
	"testing"
)

func TestSessionCapacityBoundariesAndIdempotentRelease(t *testing.T) {
	manager, _ := NewResourceManager("", 1)
	for _, limit := range []uint32{0, MaxResourcePoolSize + 1} {
		if err := manager.SetSessionCapacity(limit); err == nil {
			t.Fatal("invalid capacity accepted", limit)
		}
	}
	if err := manager.SetSessionCapacity(1); err != nil {
		t.Fatal(err)
	}
	if err := manager.AdmitSession(0); err == nil {
		t.Fatal("zero session accepted")
	}
	if err := manager.AdmitSession(1); err != nil {
		t.Fatal(err)
	}
	if err := manager.AdmitSession(1); !errors.Is(err, ErrResourceCollision) {
		t.Fatal("duplicate admission", err)
	}
	if err := manager.AdmitSession(2); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("maximum exceeded", err)
	}
	if err := manager.SetSessionCapacity(2); err == nil {
		t.Fatal("live capacity changed")
	}
	if err := manager.SetSessionCapacity(1); err != nil {
		t.Fatal("same endpoint capacity rejected", err)
	}
	manager.ReleaseSession(99)
	if err := manager.AdmitSession(2); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("unknown completion freed another slot", err)
	}
	manager.ReleaseSession(1)
	manager.ReleaseSession(1)
	if err := manager.AdmitSession(2); err != nil {
		t.Fatal(err)
	}
	if err := manager.AdmitSession(3); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("double completion freed another slot", err)
	}
	var absent *ResourceManager
	if err := absent.AdmitSession(1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal(err)
	}
}

func TestConcurrentSessionAdmissionsRespectCapacity(t *testing.T) {
	manager, _ := NewResourceManager("", 1)
	if err := manager.SetSessionCapacity(7); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan uint64, 128)
	var group sync.WaitGroup
	for id := uint64(1); id <= 128; id++ {
		group.Go(func() {
			err := manager.AdmitSession(id)
			if err == nil {
				accepted <- id
			} else if !errors.Is(err, ErrResourceExhausted) {
				t.Error(err)
			}
		})
	}
	group.Wait()
	close(accepted)
	if len(accepted) != 7 {
		t.Fatalf("admitted %d, want 7", len(accepted))
	}
	for id := range accepted {
		manager.ReleaseSession(id)
	}
	for id := uint64(1); id <= 7; id++ {
		if err := manager.AdmitSession(id); err != nil {
			t.Fatal("released capacity leaked", err)
		}
	}
}

func TestDefaultSessionCapacityMatchesStandaloneConfiguration(t *testing.T) {
	manager, _ := NewResourceManager("", 1)
	for id := uint64(1); id <= 65535; id++ {
		if err := manager.AdmitSession(id); err != nil {
			t.Fatal(id, err)
		}
	}
	if err := manager.AdmitSession(65536); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("default capacity exceeded", err)
	}
}
