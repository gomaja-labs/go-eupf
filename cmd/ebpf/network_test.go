//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMain gives every test process its own network and mount namespaces. The
// re-exec happens before Go starts test goroutines, so no thread can use the
// caller's routing table. No persistent host interfaces or bpffs pins are used.
func TestMain(m *testing.M) {
	if os.Getenv("EUPF_TEST_NAMESPACE") != "1" {
		cmd := exec.Command("unshare", "--mount", "--net", "--", os.Args[0])
		cmd.Args = append(cmd.Args, os.Args[1:]...)
		cmd.Env = append(os.Environ(), "EUPF_TEST_NAMESPACE=1")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			var e *exec.ExitError
			if errors.As(err, &e) {
				os.Exit(e.ExitCode())
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if err := setupTestNetwork(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Fuzz subprocesses must enter a fresh namespace too.
	_ = os.Unsetenv("EUPF_TEST_NAMESPACE")
	os.Exit(m.Run())
}

func setupTestNetwork() error {
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		return fmt.Errorf("private bpffs: %w", err)
	}
	commands := [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "test-egress", "type", "veth", "peer", "name", "test-peer"},
		{"link", "set", "test-egress", "up"}, {"link", "set", "test-peer", "up"},
		{"addr", "add", "198.18.1.1/24", "dev", "test-egress"},
		{"route", "add", "10.3.0.0/24", "dev", "test-egress"},
		{"route", "add", "1.1.1.1/32", "dev", "test-egress"},
		{"route", "add", "192.0.2.0/24", "dev", "test-egress"},
	}
	for _, dst := range []string{"10.3.0.10", "10.3.0.20", "10.3.0.30", "1.1.1.1", "192.0.2.3", "198.18.1.2"} {
		commands = append(commands, []string{"neigh", "add", dst, "lladdr", "02:00:00:00:00:02", "nud", "permanent", "dev", "test-egress"})
	}
	for _, args := range commands {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %v: %w: %s", args, err, out)
		}
	}
	for _, p := range []string{"/proc/sys/net/ipv4/conf/all/forwarding", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(p, []byte("1\n"), 0600); err != nil {
			return err
		}
	}
	_, err := net.InterfaceByName("test-egress")
	return err
}
