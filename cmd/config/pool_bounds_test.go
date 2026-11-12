package config

import (
	"math"
	"testing"
)

func TestValidateRejectsUnboundedResourcePools(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*UpfConfig)
	}{
		{"ipv6_subnet", func(c *UpfConfig) { c.FeatureUEIP = true; c.UEIPPool = "2001:db8::/64" }},
		{"ipv4_entire_space", func(c *UpfConfig) { c.FeatureUEIP = true; c.UEIPPool = "0.0.0.0/0" }},
		{"wrapping_teid_counter", func(c *UpfConfig) { c.FeatureFTUP = true; c.FTEIDPool = math.MaxUint32 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validLimitsConfig()
			tc.edit(&c)
			// Validation must reject these before NewResourceManager eagerly
			// enumerates the pool; allocating the pool would exhaust the test host.
			if err := c.Validate(); err == nil {
				t.Error("accepted a pool that cannot be safely enumerated at startup")
			}
		})
	}
}
