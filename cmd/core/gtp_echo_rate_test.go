package core

import (
	"net"
	"sync"
	"testing"
	"time"
)

// Echo responses mirror the sequence number; all packets use synthetic loopback endpoints.
func echoTestPeer(t *testing.T) (*net.UDPConn, <-chan struct{}) {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	received := make(chan struct{}, 100)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := peer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			buf[1] = 2
			_, _ = peer.WriteToUDP(buf[:n], addr)
			received <- struct{}{}
		}
	}()
	return peer, received
}

func TestGTPEchoPerPathRateAfterTimerEdit(t *testing.T) {
	peer, received := echoTestPeer(t)
	manager := NewGtpPathManager("127.0.0.1:0", time.Hour)
	defer manager.Stop()
	manager.AddGtpPath(peer.LocalAddr().String())
	if _, err := manager.sendEcho(peer.LocalAddr().String(), 1); err != nil {
		t.Fatal(err)
	}
	<-received
	// A ready ticker (or a replaced ticker) must never bypass the per-path minimum.
	manager.UpdateGtpPath(nil)
	manager.UpdateGtpPath([]string{peer.LocalAddr().String()})
	manager.UpdateCheckTicker(time.NewTicker(time.Millisecond))
	manager.Run()
	select {
	case <-received:
		t.Fatal("second Echo Request on the same path within 60 seconds")
	case <-time.After(30 * time.Millisecond):
	}
	other, _ := echoTestPeer(t)
	if _, err := manager.sendEcho(other.LocalAddr().String(), 1); err != nil {
		t.Fatalf("independent path blocked: %v", err)
	}
}

func TestGTPEchoConcurrentAddressUpdateAndSend(t *testing.T) {
	peer, _ := echoTestPeer(t)
	manager := NewGtpPathManager("127.0.0.1:0", time.Hour)
	defer manager.Stop()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			manager.UpdateLocalAddress("127.0.0.1:0")
		}
	})
	wg.Go(func() {
		for range 100 {
			_, _ = manager.sendEcho(peer.LocalAddr().String(), 1)
		}
	})
	wg.Wait()
}
