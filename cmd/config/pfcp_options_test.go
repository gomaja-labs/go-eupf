package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestPFCPOptionsDecodeAndValidate(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(strings.NewReader("pfcp_peer_allow_list: [192.0.2.0/24, '2001:db8::1']\npfcp_request_timeout: 2\npfcp_request_retries: 4\npfcp_response_retention: 30\npfcp_max_transactions: 128\npfcp_max_associations: 16\nheartbeat_failure_grace: 15\n"))
	if err != nil {
		t.Fatal(err)
	}
	var config UpfConfig
	if err := v.UnmarshalExact(&config); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidatePFCP(); err != nil {
		t.Fatal(err)
	}
	if len(config.PfcpPeerAllowList) != 2 || config.PfcpRequestTimeout != 2 || config.PfcpRequestRetries != 4 || config.PfcpResponseRetention != 30 || config.PfcpMaxTransactions != 128 || config.PfcpMaxAssociations != 16 || config.HeartbeatFailureGrace != 15 {
		t.Fatal("incorrect decoded PFCP options")
	}
}

func TestPFCPOptionBounds(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config UpfConfig
		valid  bool
	}{
		{"defaults", UpfConfig{}, true},
		{"bad-peer", UpfConfig{PfcpPeerAllowList: []string{"invalid"}}, false},
		{"bad-prefix", UpfConfig{PfcpPeerAllowList: []string{"192.0.2.0/33"}}, false},
		{"broad-mapped", UpfConfig{PfcpPeerAllowList: []string{"::ffff:192.0.2.1/80"}}, false},
		{"short-retention", UpfConfig{PfcpRequestTimeout: 5, PfcpRequestRetries: 3, PfcpResponseRetention: 19}, false},
		{"exact-retention", UpfConfig{PfcpRequestTimeout: 5, PfcpRequestRetries: 3, PfcpResponseRetention: 20}, true},
		{"retry-bound", UpfConfig{PfcpRequestRetries: 101}, false},
		{"timeout-bound", UpfConfig{PfcpRequestTimeout: 3601}, false},
		{"capacity-bound", UpfConfig{PfcpMaxTransactions: 65537}, false},
		{"association-bound", UpfConfig{PfcpMaxAssociations: 65537}, false},
		{"grace-bound", UpfConfig{HeartbeatFailureGrace: 86401}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.ValidatePFCP(); (err == nil) != tt.valid {
				t.Fatalf("valid=%t err=%v", tt.valid, err)
			}
		})
	}
}
