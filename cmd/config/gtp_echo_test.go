package config

import (
	"strings"
	"testing"
)

func TestGTPEchoMinimumInterval(t *testing.T) {
	for _, seconds := range []uint32{0, 1, 59, 60, 61} {
		c := validLimitsConfig()
		c.GtpEchoInterval = seconds
		err := c.Validate()
		if seconds < 60 {
			if err == nil || !strings.Contains(err.Error(), "gtp_echo_interval") || !strings.Contains(err.Error(), "7.2.1") {
				t.Errorf("%d seconds: want key and clause in error, got %v", seconds, err)
			}
		} else if err != nil {
			t.Errorf("%d seconds: %v", seconds, err)
		}
	}
}

func TestGTPEchoDefaultIs60Seconds(t *testing.T) {
	initConfigFixture(t, "")
	if value := commonConfigV.GetUint32("gtp_echo_interval"); value != 60 {
		t.Fatalf("gtp_echo_interval default=%d", value)
	}
}
