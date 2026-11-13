package service

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestRestartReservesAutomaticIPv4ForRestorationWindow(t *testing.T) {
	old, err := newResourceManagerAt("192.0.2.0/30", 3, time.Unix(1800000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	ip, err := old.IPAM.AllocateIP(1)
	if err != nil {
		t.Fatal(err)
	}
	teid, err := old.FTEIDM.AllocateTEID(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newResourceManagerAt("192.0.2.0/30", 3, time.Unix(1800000001, 0))
	if err != nil {
		t.Fatal(err)
	}
	restarted.HoldAutomaticIPv4Until(time.Now().Add(time.Minute))
	if _, err := restarted.IPAM.AllocateIP(2); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("previous UE IP immediately reused after restart")
	}

	// RESTI can reserve the original identifiers throughout the automatic hold.
	if err := restarted.IPAM.ReserveIP(1, ip); err != nil {
		t.Fatal(err)
	}
	if err := restarted.FTEIDM.ReserveTEID(1, 1, teid); err != nil {
		t.Fatal(err)
	}
	if err := restarted.IPAM.ReserveIP(3, ip); !errors.Is(err, ErrResourceCollision) {
		t.Fatal("restoration stole a reserved UE IP")
	}
	if err := restarted.FTEIDM.ReserveTEID(3, 1, teid); !errors.Is(err, ErrResourceCollision) {
		t.Fatal("restoration stole a reserved TEID")
	}
	restarted.HoldAutomaticIPv4Until(time.Now().Add(-time.Second))
	nextIP, err := restarted.IPAM.AllocateIP(2)
	if err != nil || nextIP.Equal(ip) {
		t.Fatalf("post-window UE IP %s: %v", nextIP, err)
	}
	nextTEID, err := restarted.FTEIDM.AllocateTEID(2, 1)
	if err != nil || nextTEID == teid {
		t.Fatalf("post-window TEID %d: %v", nextTEID, err)
	}
}

func TestFreeChainPoolBoundaries(t *testing.T) {
	manager, err := NewResourceManager("10.60.0.0/16", 65535)
	if err != nil {
		t.Fatal(err)
	}
	for id := uint64(1); id <= 65535; id++ {
		teid, err := manager.FTEIDM.AllocateTEID(id, 1)
		if err != nil || teid != manager.FTEIDM.generationBase+uint32(id) {
			t.Fatalf("TEID %d: %d %v", id, teid, err)
		}
		ip, err := manager.IPAM.AllocateIP(id)
		if err != nil {
			t.Fatal(err)
		}
		if id == 65535 && !ip.Equal(net.ParseIP("10.60.255.255")) {
			t.Fatalf("last IPv4 %s", ip)
		}
	}
	if _, err := manager.FTEIDM.AllocateTEID(65536, 1); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("TEID chain did not exhaust")
	}
	if _, err := manager.IPAM.AllocateIP(65536); !errors.Is(err, ErrResourceExhausted) {
		t.Fatal("IPv4 chain did not exhaust")
	}
	manager.FTEIDM.ReleaseTEID(65535)
	manager.IPAM.ReleaseIP(65535)
	if id, err := manager.FTEIDM.AllocateTEID(65536, 1); err != nil || id != manager.FTEIDM.generationBase+65535 {
		t.Fatalf("last TEID reuse: %d %v", id, err)
	}
	if ip, err := manager.IPAM.AllocateIP(65536); err != nil || !ip.Equal(net.ParseIP("10.60.255.255")) {
		t.Fatalf("last IPv4 reuse: %s %v", ip, err)
	}
}

func TestIPv6AllocationPoolIsRejectedAndExplicitPrefixesRemainReserved(t *testing.T) {
	for _, prefix := range []string{"2001:db8::/64", "2001:db8::/120", "2001:db8::/128"} {
		if _, err := NewResourceManager(prefix, 1); err == nil {
			t.Fatalf("unsupported IPv6 allocation pool %s accepted", prefix)
		}
	}
	manager, err := NewResourceManager("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"2001:db8::", "2001:db8::ff", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"} {
		ip := net.ParseIP(address)
		if err := manager.IPAM.ReserveIPv6Prefix(1, ip, net.CIDRMask(128, 128)); err != nil {
			t.Fatal(err)
		}
		if err := manager.IPAM.ReserveIP(2, ip); !errors.Is(err, ErrResourceCollision) {
			t.Fatal("IPv6 last-host prefix collision lost")
		}
	}
	manager.IPAM.ReleaseIP(1)
	if err := manager.IPAM.ReserveIP(2, net.ParseIP("2001:db8::ff")); err != nil {
		t.Fatal(err)
	}
}
