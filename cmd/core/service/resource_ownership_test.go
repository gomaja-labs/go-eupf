package service

import (
	"net"
	"sync"
	"testing"
)

func TestIPAllocationRetainsOwner(t *testing.T) {
	manager, err := NewResourceManager("192.0.2.0/30", 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.IPAM.AllocateIP(10)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		again, err := manager.IPAM.AllocateIP(10)
		if err != nil || !first.Equal(again) {
			t.Fatalf("repeated owner allocation = %v, %v; want %v", again, err, first)
		}
	}
	second, err := manager.IPAM.AllocateIP(20)
	if err != nil || first.Equal(second) {
		t.Fatalf("distinct owner allocation = %v, %v", second, err)
	}
	third, err := manager.IPAM.AllocateIP(30)
	if err != nil || first.Equal(third) || second.Equal(third) {
		t.Fatalf("distinct owner allocation = %v, %v", third, err)
	}
	if _, err := manager.IPAM.AllocateIP(40); err == nil {
		t.Fatal("exhausted pool accepted a new owner")
	}
	manager.IPAM.ReleaseIP(10)
	manager.IPAM.ReleaseIP(10)
	reused, err := manager.IPAM.AllocateIP(40)
	if err != nil || !first.Equal(reused) {
		t.Fatalf("released address = %v, %v; want %v", reused, err, first)
	}
	if _, err := manager.IPAM.AllocateIP(50); err == nil {
		t.Fatal("double release created a duplicate free address")
	}
}

func TestIPAllocationOwnsReturnedBytes(t *testing.T) {
	manager, err := NewResourceManager("192.0.2.0/30", 0)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := manager.IPAM.AllocateIP(10)
	if err != nil {
		t.Fatal(err)
	}
	want := append(net.IP(nil), ip...)
	clear(ip)
	again, err := manager.IPAM.AllocateIP(10)
	if err != nil || !again.Equal(want) {
		t.Fatalf("caller changed owned address: %v, %v; want %v", again, err, want)
	}
	clear(again)
	manager.IPAM.ReleaseIP(10)
	manager.IPAM.ReleaseIP(10)
	_, err = manager.IPAM.AllocateIP(20)
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.IPAM.AllocateIP(30)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := manager.IPAM.AllocateIP(40)
	if err != nil || !reused.Equal(want) {
		t.Fatalf("released address corrupted: %v, %v; want %v", reused, err, want)
	}
}

func TestTEIDAllocationRetainsOwner(t *testing.T) {
	manager, err := NewResourceManager("", 3)
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.FTEIDM.AllocateTEID(10, 1)
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		again, err := manager.FTEIDM.AllocateTEID(10, 1)
		if err != nil || again != first {
			t.Fatalf("repeated owner allocation = %d, %v; want %d", again, err, first)
		}
	}
	second, err := manager.FTEIDM.AllocateTEID(10, 2)
	if err != nil || second == first {
		t.Fatalf("distinct PDR allocation = %d, %v", second, err)
	}
	third, err := manager.FTEIDM.AllocateTEID(20, 1)
	if err != nil || third == first || third == second {
		t.Fatalf("distinct session allocation = %d, %v", third, err)
	}
	if _, err := manager.FTEIDM.AllocateTEID(30, 1); err == nil {
		t.Fatal("exhausted pool accepted a new owner")
	}
	manager.FTEIDM.ReleaseTEID(10)
	manager.FTEIDM.ReleaseTEID(10)
	reused := make(map[uint32]bool)
	for _, id := range []uint32{1, 2} {
		teid, err := manager.FTEIDM.AllocateTEID(30, id)
		if err != nil || (teid != first && teid != second) || reused[teid] {
			t.Fatalf("released TEID = %d, %v", teid, err)
		}
		reused[teid] = true
	}
	if _, err := manager.FTEIDM.AllocateTEID(40, 1); err == nil {
		t.Fatal("double release created a duplicate free TEID")
	}
}

func TestConcurrentAllocationForOneOwner(t *testing.T) {
	manager, err := NewResourceManager("192.0.2.0/30", 1)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			ip, err := manager.IPAM.AllocateIP(10)
			if err != nil || !ip.Equal(net.ParseIP("192.0.2.1")) {
				t.Errorf("IP = %v, %v", ip, err)
			}
			teid, err := manager.FTEIDM.AllocateTEID(10, 1)
			if err != nil || teid != 1 {
				t.Errorf("TEID = %d, %v", teid, err)
			}
		})
	}
	group.Wait()
}
