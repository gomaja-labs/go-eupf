package config

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestInactivityReleaseConfigurationSources(t *testing.T) {
	for _, source := range []string{"default", "file", "environment", "flag"} {
		t.Run(source, func(t *testing.T) {
			text := ""
			if source == "file" {
				text = "inactivity_release_timeout: 7\n"
			}
			initConfigFixture(t, text)
			expected := uint32(0)
			if source != "default" {
				expected = 7
			}
			if source == "environment" {
				t.Setenv("UPF_INACTIVITY_RELEASE_TIMEOUT", "7")
			}
			if source == "flag" {
				if err := pflag.Set("inactivity-release-timeout", "7"); err != nil {
					t.Fatal(err)
				}
			}
			var c UpfConfig
			if err := c.Unmarshal(); err != nil {
				t.Fatal(err)
			}
			if c.InactivityReleaseTimeout != expected {
				t.Fatalf("source %s gave %d want %d", source, c.InactivityReleaseTimeout, expected)
			}
			if err := c.ValidatePFCP(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestInactivityReleaseConfigurationBound(t *testing.T) {
	for _, seconds := range []uint32{0, 1, 86400, 86401, ^uint32(0)} {
		c := UpfConfig{InactivityReleaseTimeout: seconds}
		if err := c.ValidatePFCP(); (err == nil) != (seconds <= 86400) {
			t.Fatalf("seconds=%d error=%v", seconds, err)
		}
	}
}
