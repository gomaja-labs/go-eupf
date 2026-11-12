package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestHeartbeatZeroDisablesProbes(t *testing.T) {
	c := validLimitsConfig()
	c.HeartbeatTimeout = 0
	c.HeartbeatInterval = 0
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestReadConfigFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, data                string
		exists, explicit, wantErr bool
	}{
		{"malformed", "pfcp_peer_allow_list: [bad", true, false, true},
		{"explicit_missing", "", false, true, true},
		{"default_missing", "", false, false, false},
		{"valid", "logging_level: info", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if tc.exists {
				if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			v := viper.New()
			v.SetConfigFile(path)
			if err := readConfig(v, tc.explicit); (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestValidationIsIdempotent(t *testing.T) {
	c := validLimitsConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
