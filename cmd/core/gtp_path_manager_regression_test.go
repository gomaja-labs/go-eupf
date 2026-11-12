package core

import (
	"sync"
	"testing"
	"time"
)

func TestGtpPathUpdatePreservesSequence(t *testing.T) {
	manager := NewGtpPathManager("127.0.0.1:0", time.Hour)
	defer manager.Stop()
	manager.AddGtpPath("127.0.0.1:2152")
	manager.peers["127.0.0.1:2152"] = 7
	manager.UpdateGtpPath([]string{"127.0.0.1:2152"})
	if manager.peers["127.0.0.1:2152"] != 7 {
		t.Fatal("unchanged GTP path lost sequence state")
	}
}
func TestGtpPathConcurrentConfiguration(t *testing.T) {
	manager := NewGtpPathManager("127.0.0.1:0", time.Hour)
	manager.Run()
	defer manager.Stop()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			manager.AddGtpPath("127.0.0.1:2152")
			manager.UpdateLocalAddress("127.0.0.1:0")
			manager.UpdateCheckTicker(time.NewTicker(time.Hour))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			manager.UpdateGtpPath([]string{"127.0.0.1:2152"})
			manager.UpdateLocalAddress("127.0.0.2:0")
			manager.UpdateCheckTicker(time.NewTicker(time.Hour))
		}
	}()
	wg.Wait()
}
