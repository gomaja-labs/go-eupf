package service

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Keep a regression of eager unbounded enumeration from hanging the suite or
// exhausting the machine: probes run in a short-lived child, never in this test.
func TestResourcePoolBounds(t *testing.T) {
	if probe := os.Getenv("EUPF_RESOURCE_POOL_PROBE"); probe != "" {
		var prefix string
		var teids uint32
		switch probe {
		case "IPv4":
			prefix = "0.0.0.0/0"
		case "IPv6":
			prefix = "2001::/16"
		case "TEID":
			teids = ^uint32(0)
		case "TEID limit":
			teids = 1<<20 + 1
		}
		if _, err := NewResourceManager(prefix, teids); err == nil {
			t.Fatalf("unbounded %s pool accepted", probe)
		}
		return
	}
	for _, probe := range []string{"IPv4", "IPv6", "TEID", "TEID limit"} {
		t.Run(probe, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestResourcePoolBounds$")
			cmd.Env = append(os.Environ(), "EUPF_RESOURCE_POOL_PROBE="+probe)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("pool did not reject promptly: %v: %s", err, output)
			}
		})
	}
}
