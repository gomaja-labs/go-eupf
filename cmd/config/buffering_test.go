package config

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestBufferingRejectsInvalidAllocationAndRetention(t *testing.T) {
	for _, c := range []UpfConfig{{BufferPackets: 65537}, {BufferPerSession: 65}, {BufferPackets: 3, BufferPerSession: 4}, {BufferRetentionSeconds: 86401}} {
		if err := c.ValidateBuffering(); err == nil {
			t.Fatalf("accepted invalid buffering settings: %+v", c.Buffering())
		}
	}
	if err := (&UpfConfig{}).ValidateBuffering(); err != nil {
		t.Fatal(err)
	}
	if got := (&UpfConfig{}).Buffering(); got.Packets != 4096 || got.PerSession != 4 || got.RetentionSeconds != 30 {
		t.Fatalf("defaults: %+v", got)
	}
}

func TestMemoryBudgetIncludesPacketPoolAndBufferLifetimes(t *testing.T) {
	c := UpfConfig{MaxSessions: 1024, PfcpReplayMemoryMiB: 128, BufferPackets: 65536, BufferPerSession: 64}
	if _, err := c.PFCPMemoryPlan(512*mib, 64*mib); err == nil {
		t.Fatal("large packet pool was omitted from container admission")
	}
	c = UpfConfig{MaxSessions: 1024, PfcpReplayMemoryMiB: 64}
	if _, err := c.PFCPMemoryPlan(512*mib, 88*mib); err != nil {
		t.Fatalf("chart budgets cannot fit: %v", err)
	}
}

func TestBufferingSettingsFileFlagAndEnvironment(t *testing.T) {
	for _, source := range []string{"file", "flag", "environment"} {
		t.Run(source, func(t *testing.T) {
			initConfigFixture(t, "buffer_packets: 8\nbuffer_per_session: 2\nbuffer_retention_seconds: 5\n")
			want := uint32(8)
			if source == "flag" {
				if err := pflag.CommandLine.Set("buffer-packets", "16"); err != nil {
					t.Fatal(err)
				}
				want = 16
			}
			if source == "environment" {
				t.Setenv("UPF_BUFFER_PACKETS", "32")
				want = 32
			}
			var c UpfConfig
			if err := c.Unmarshal(); err != nil {
				t.Fatal(err)
			}
			if err := c.ValidateBuffering(); err != nil {
				t.Fatal(err)
			}
			if got := c.Buffering(); got.Packets != want || got.PerSession != 2 || got.RetentionSeconds != 5 {
				t.Fatalf("%s: %+v", source, got)
			}
		})
	}
}
