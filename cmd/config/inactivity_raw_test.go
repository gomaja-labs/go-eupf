package config

import "testing"

func TestInactivityReleaseRejectsLossyConfiguration(t *testing.T) {
	for _, raw := range []string{"4294967297", "-4294967295", "1.5", "true"} {
		t.Run(raw, func(t *testing.T) {
			initConfigFixture(t, "inactivity_release_timeout: "+raw+"\n")
			var c UpfConfig
			err := c.Unmarshal()
			if err == nil {
				err = c.ValidatePFCP()
			}
			if err == nil {
				t.Fatalf("invalid raw timeout %s accepted as %d seconds", raw, c.InactivityReleaseTimeout)
			}
		})
	}
}
