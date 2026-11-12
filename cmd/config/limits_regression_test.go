package config

import "testing"

func validLimitsConfig() UpfConfig {
	return UpfConfig{
		XDPAttachMode: "generic", ApiAddress: "127.0.0.1:8080",
		PfcpAddress: "127.0.0.1:8805", PfcpNodeId: "127.0.0.1",
		MetricsAddress: "127.0.0.1:9090", N3Address: "192.0.2.1", N9Address: "192.0.2.1",
		N3AdvertisedAddress: "192.0.2.1", N3AdvertisedAddress5G: "192.0.2.1", N9AdvertisedAddress: "192.0.2.1",
		HeartbeatInterval: 5, HeartbeatTimeout: 5,
		GtpEchoInterval: 60, MaxSessions: 1024, AssociationSetupTimeout: 5,
		LoggingLevel: "info", UEIPPool: "192.0.2.0/30", Ip6RaPrefix: "2001:db8::/64",
		TraceMaxDumpFiles: 1, TraceMaxDumpSize: 1024, TraceMaxDumpPackets: 10,
	}
}

func TestValidateRejectsUnsafeLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*UpfConfig)
	}{
		{"zero_association_timer", func(c *UpfConfig) { c.AssociationSetupTimeout = 0 }},
		{"overflowing_session_count", func(c *UpfConfig) { c.MaxSessions = 1 << 31 }},
		{"negative_trace_files", func(c *UpfConfig) { c.TraceMaxDumpFiles = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validLimitsConfig()
			if err := c.Validate(); err != nil {
				t.Fatalf("invalid fixture: %v", err)
			}
			c = validLimitsConfig()
			tc.edit(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("unsafe %s accepted (PDR map size %d)", tc.name, c.PdrMapSize)
			}
		})
	}
}
