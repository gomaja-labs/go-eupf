//go:build linux

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"golang.org/x/sys/unix"
)

func TestBufferSenderStartupRemovesOnlyStalePrivateLinks(t *testing.T) {
	command := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	plane, _, _, _, _, _ := packetBufferFixtureStartOptions(t, false, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
	plane.StartBufferPrograms(context.Background())
	program, err := plane.BufferKernelIngressProgram()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = program.Close() }()
	create := func() *bufferKernelLink {
		t.Helper()
		link, err := newBufferKernelLink(program.FD(), func(*bufferKernelLink) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = link.Close() })
		return link
	}
	stale, live, secondLive := create(), create(), create()
	// Simulate exit immediately after creation: the kernel keeps the veth pair,
	// but closes every process-owned descriptor. Reclamation cannot depend on
	// later alias writes or on recording the returned interface index.
	if err := unix.Close(stale.ownerFD); err != nil {
		t.Fatal(err)
	}
	stale.ownerFD = -1
	stale.index = 0
	users := []string{"eubuser", "eub00000000000z", "eub00000000000A", "eub00000000000"}
	for i, name := range users {
		command("link", "add", name, "type", "veth", "peer", "name", fmt.Sprintf("userpeer%d", i))
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
	}
	sender, err := newBufferPacketSender(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	if _, err := net.InterfaceByName(stale.name); err == nil {
		t.Fatal("stale private veth survived startup")
	}
	for _, name := range append(users, live.name, secondLive.name) {
		if _, err := net.InterfaceByName(name); err != nil {
			t.Fatalf("removed live or unmarked link %s: %v", name, err)
		}
	}
}

func TestBufferSenderCloseStopsLinkCreationAfterVerifier(t *testing.T) {
	// Observe the real creation window without joining kernel verification.
	plane, _, _, _, _, _ := packetBufferFixtureStartOptions(t, false, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
	plane.StartBufferPrograms(context.Background())
	prog, err := plane.BufferKernelIngressProgram()
	if err != nil {
		t.Fatal(err)
	}
	_ = prog.Close()
	observed := 0
attempts:
	for range 10 {
		raw, err := newBufferPacketSender(plane)
		if err != nil {
			t.Fatal(err)
		}
		sender := raw.(*bufferPacketSender)
		done := make(chan error, 1)
		go func() { done <- sender.initialize(context.Background()) }()
		found := false
		deadline := time.Now().Add(time.Second)
		for !found && time.Now().Before(deadline) {
			interfaces, err := net.Interfaces()
			if err != nil {
				t.Fatal(err)
			}
			for _, iface := range interfaces {
				if strings.HasPrefix(iface.Name, "eub") {
					found = true
					break
				}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
				_ = sender.Close()
				continue attempts
			default:
			}
		}
		observed++
		if err := sender.Close(); err != nil {
			t.Fatal(err)
		}
		interfaces, err := net.Interfaces()
		if err != nil {
			t.Fatal(err)
		}
		for _, iface := range interfaces {
			if strings.HasPrefix(iface.Name, "eub") {
				t.Errorf("private link %s survived Close", iface.Name)
			}
		}
		if err := <-done; err != nil && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "canceled") && !errors.Is(err, unix.ENODEV) {
			t.Logf("initialization after close: %v", err)
		}
		if t.Failed() {
			return
		}
	}
	if observed == 0 {
		t.Fatal("did not observe link creation before initialization completed")
	}
}
