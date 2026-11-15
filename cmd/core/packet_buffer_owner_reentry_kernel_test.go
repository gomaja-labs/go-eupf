//go:build linux

package core

import (
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"sync/atomic"
	"testing"
	"time"
)

// BUFF requested again right after the drain guard was detached, before the
// retiring owner was released: the modification must not fail.
func TestRebufferWhileOwnerRetires(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixture(t)
	packetBufferRoute(t, plane)
	if err := buffering.sender.Close(); err != nil {
		t.Fatal(err)
	}
	var sends atomic.Int32
	buffering.sender = bufferSenderFunc(func(ebpf.RenderedBuffer) error { sends.Add(1); return nil })
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	_ = switchBufferedFARToForward(t, conn, assoc, session)
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn.stateMu.Lock()
		current := assoc.Sessions[11]
		if current.buffers == nil {
			buffering.mu.Lock()
			retiring := buffering.owners[11] != nil
			buffering.mu.Unlock()
			resumed, err := setBufferAction(conn, assoc, current, 12)
			conn.stateMu.Unlock()
			t.Logf("owner still registered when BUFF was requested: %v", retiring)
			if err != nil {
				t.Fatalf("BUFF|NOCP right after drain retirement rejected: %v", err)
			}
			buffering.mu.Lock()
			reserved := buffering.reserved
			buffering.mu.Unlock()
			if reserved != 1 {
				t.Fatalf("resuming reserved a second admission slot: %d", reserved)
			}
			if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 101)); err != nil {
				t.Fatal(err)
			}
			_ = switchBufferedFARToForward(t, conn, assoc, resumed)
			for time.Now().Before(deadline) {
				buffering.mu.Lock()
				reserved = buffering.reserved
				buffering.mu.Unlock()
				if reserved == 0 {
					if sends.Load() != 2 {
						t.Fatalf("old/new lifetime deliveries=%d want 2", sends.Load())
					}
					if outstanding, _, err := plane.BufferPoolUsage(); err != nil || outstanding != 0 {
						t.Fatalf("resumed owner leaked packet credit: %d %v", outstanding, err)
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("resumed owner did not return its single reservation")
		}
		conn.stateMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("drain did not detach")
		}
		time.Sleep(50 * time.Microsecond)
	}
}
