package config

import (
	"strings"
	"testing"
)

func TestAPIExposure(t *testing.T) {
	for _, tc := range []struct {
		address, token string
		invalid        bool
	}{
		{"127.0.0.1:8080", "", false}, {"[::1]:8080", "", false}, {"localhost:8080", "", false},
		{":8080", "", true}, {"0.0.0.0:8080", "", true}, {"192.0.2.1:8080", "", true},
		{"192.0.2.1:8080", "test-token", false}, {":8080", " ", true},
	} {
		t.Run(tc.address+tc.token, func(t *testing.T) {
			cfg := UpfConfig{ApiAddress: tc.address, ApiToken: tc.token}
			err := cfg.ValidateAPIExposure()
			if (err != nil) != tc.invalid {
				t.Fatalf("error=%v invalid=%v", err, tc.invalid)
			}
		})
	}
}

func TestConfigurationLimitsNameKeys(t *testing.T) {
	for _, tc := range []struct {
		key  string
		edit func(*UpfConfig)
	}{
		{"association_setup_timeout", func(c *UpfConfig) { c.AssociationSetupTimeout = 0 }},
		{"heartbeat_interval", func(c *UpfConfig) { c.HeartbeatInterval = 0 }},
		{"heartbeat_timeout", func(c *UpfConfig) { c.HeartbeatTimeout = 0 }},
		{"max_sessions", func(c *UpfConfig) { c.MaxSessions = 1 << 31 }},
		{"pdr_map_size", func(c *UpfConfig) { c.PdrMapSize = 1 << 31 }},
		{"trace_max_size", func(c *UpfConfig) { c.TraceMaxDumpSize = 0 }},
		{"trace_max_packets", func(c *UpfConfig) { c.TraceMaxDumpPackets = -1 }},
		{"api_allowed_origins", func(c *UpfConfig) { c.ApiAllowedOrigins = []string{"https://"} }},
	} {
		t.Run(tc.key, func(t *testing.T) {
			cfg := validLimitsConfig()
			tc.edit(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("want error naming %s, got %v", tc.key, err)
			}
		})
	}
}
