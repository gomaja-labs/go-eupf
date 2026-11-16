//go:build linux

package core

import (
	"context"
	"errors"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"golang.org/x/sys/unix"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestBufferSenderStartupRemovesOnlyStalePrivateLinks(t *testing.T) {
	command := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	stale := "go-eupf-buffer:00000000000000000000000000000001"
	live := "go-eupf-buffer:00000000000000000000000000000002"
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: "@" + live}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"eubstale", "eublive", "eubuser"} {
		command("link", "add", name, "type", "veth", "peer", "name", name+"p")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
	}
	command("link", "set", "dev", "eubstale", "alias", stale)
	command("link", "set", "dev", "eublive", "alias", live)
	sender, err := newBufferPacketSender(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	if _, err := net.InterfaceByName("eubstale"); err == nil {
		t.Fatal("stale private veth survived startup")
	}
	for _, name := range []string{"eublive", "eubuser"} {
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
			case <-done:
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
