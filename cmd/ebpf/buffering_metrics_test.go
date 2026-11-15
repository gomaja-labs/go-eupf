//go:build linux

package ebpf

import (
	"net"
	"testing"
)

func TestBufferCanceledAdmissionHasItsOwnDiscardReason(t *testing.T) {
	b := loadDatapath(t)
	if err := b.CreateBufferAnchor(42, 1, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateFar(3, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 1, Mode: BufferDiscard}); err != nil {
		t.Fatal(err)
	}
	input := ethernetDatapath(t, 0x0800, udpDatapath(t, false))
	if action, _, err := b.UpfIpEntrypointFunc.Test(input); err != nil || action != 1 {
		t.Fatalf("action=%d error=%v", action, err)
	}
	retained, overflow, canceled, err := b.BufferPoolMetrics()
	if err != nil || retained != 0 || overflow != 0 || canceled != 1 {
		t.Fatalf("metrics=%d/%d/%d error=%v", retained, overflow, canceled, err)
	}
	overflow, canceled, err = b.BufferLifetimeDiscards(42)
	if err != nil || overflow != 0 || canceled != 1 {
		t.Fatalf("lifetime=%d/%d error=%v", overflow, canceled, err)
	}
}
