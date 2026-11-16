//go:build linux

package core

import (
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
)

func waitBufferStorage(t *testing.T, buffering *PacketBuffering, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		buffering.mu.Lock()
		held := len(buffering.entries) - len(buffering.free)
		buffering.mu.Unlock()
		if held == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("held=%d want=%d", held, want)
		}
		time.Sleep(time.Millisecond)
	}
}
func TestPacketBufferCancellationReclaimsPackets(t *testing.T) {
	for _, outcome := range []string{"DROP", "DROBU", "FAR removal", "BAR removal", "stop duration"} {
		t.Run(outcome, func(t *testing.T) {
			plane, buffering, conn, assoc, before, _ := publishPacketBufferFixture(t)
			if outcome == "BAR removal" || outcome == "stop duration" {
				before = installPacketBufferDuration(t, conn, assoc, before)
			}
			ids := []uint16{100, 101}
			if outcome == "BAR removal" || outcome == "stop duration" {
				ids = ids[:1]
			}
			for _, id := range ids {
				action, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id))
				if err != nil || action != 1 {
					t.Fatalf("admit=%d %v", action, err)
				}
			}
			waitBufferStorage(t, buffering, len(ids))
			old := before.buffers.cycles[1]
			conn.stateMu.Lock()
			after := cloneSession(before)
			switch outcome {
			case "DROP":
				far := after.FARs[1]
				far.FarInfo.Action = 1
				after.FARs[1] = far
			case "FAR removal":
				delete(after.FARs, 1)
				delete(after.PDRs, 9)
			case "BAR removal":
				after.bar = nil
				far := after.FARs[1]
				far.BARID = nil
				after.FARs[1] = far
			case "stop duration":
				if err := updateBAR(after, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0), ie.NewDLBufferingDuration(0))); err != nil {
					conn.stateMu.Unlock()
					t.Fatal(err)
				}
			}
			start, finish := conn.prepareSessionMutation(after, updateSessionMutation, true)
			conn.stagePacketBuffering(assoc, before, after, updateSessionMutation, outcome == "DROBU")
			err := start()
			if err == nil {
				err = finish(true)
			}
			if err != nil {
				_ = finish(false)
				conn.stateMu.Unlock()
				t.Fatal(err)
			}
			assoc.Sessions[after.LocalSEID] = after
			conn.stateMu.Unlock()
			waitBufferStorage(t, buffering, 0)
			conn.stateMu.RLock()
			completed := old.completed
			conn.stateMu.RUnlock()
			if completed != uint64(len(ids)) {
				t.Fatalf("canceled packets not acknowledged: %d", completed)
			}
			select {
			case err := <-buffering.Failures():
				t.Fatal(err)
			default:
			}
			// Every retained descriptor and global kernel credit has been returned.
			outstanding, _, err := plane.BufferPoolUsage()
			if err != nil {
				t.Fatal(err)
			}
			if outstanding != 0 {
				t.Fatalf("cancellation retained %d global credits", outstanding)
			}
			if outcome != "stop duration" {
				conn.stateMu.RLock()
				canceled := old.canceled
				conn.stateMu.RUnlock()
				if !canceled {
					t.Fatal("old lifetime remained active")
				}
			}
			// Stop-duration preserves BUFF and the BAR for later arrivals; other
			// cancellation outcomes either remove buffering or create a fresh cookie.
			if outcome == "stop duration" || outcome == "DROBU" || outcome == "BAR removal" {
				action, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 102))
				if err != nil || action != 1 {
					t.Fatalf("later arrival=%d %v", action, err)
				}
				waitBufferStorage(t, buffering, 1)
			}
		})
	}
}
