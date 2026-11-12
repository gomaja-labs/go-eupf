package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/config"
)

func TestConfigRequestsSendCompleteSections(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		path string
		keys []string
		send func(*EupfHttpRepository) error
	}{
		{"logging_level", []string{"logging_level"}, func(r *EupfHttpRepository) error { return r.RestoreConfigLoggingLevel(ctx, "info", "") }},
		{"logging_caller", []string{"logging_caller"}, func(r *EupfHttpRepository) error { return r.RestoreConfigLoggingCaller(ctx, false, "") }},
		{"dataplane_ebpf", []string{"interface_name", "xdp_attach_mode"}, func(r *EupfHttpRepository) error { return r.RestoreConfigDataPlaneEbpf(ctx, nil, "generic", "") }},
		{"dataplane_addresses", []string{"n3_address", "n9_address"}, func(r *EupfHttpRepository) error {
			return r.RestoreConfigDataPlaneAddresses(ctx, "192.0.2.1", "192.0.2.2", "")
		}},
		{"pfcp_n4", []string{"pfcp_address", "pfcp_node_id", "pfcp_remote_node"}, func(r *EupfHttpRepository) error { return r.RestoreConfigPFCPN4(ctx, ":8805", "127.0.0.1", nil, "") }},
		{"pfcp_sxa", []string{"sxa_address", "sxa_node_id", "sxa_remote_node"}, func(r *EupfHttpRepository) error { return r.RestoreConfigPFCPSxa(ctx, ":8805", "127.0.0.1", nil, "") }},
		{"pfcp_sxb", []string{"sxb_address", "sxb_node_id", "sxb_remote_node"}, func(r *EupfHttpRepository) error { return r.RestoreConfigPFCPSxb(ctx, ":8805", "127.0.0.1", nil, "") }},
		{"pfcp_timers", []string{"association_setup_timeout", "heartbeat_timeout"}, func(r *EupfHttpRepository) error { return r.RestoreConfigPFCPTimers(ctx, 5, 0, "") }},
		{"gtp_path", []string{"gtp_peer", "gtp_echo_interval"}, func(r *EupfHttpRepository) error { return r.RestoreConfigGTPPath(ctx, nil, 60, "") }},
	} {
		t.Run(tc.path, func(t *testing.T) {
			called := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called <- struct{}{}
				if r.Method != http.MethodPost || r.URL.Path != "/config/"+tc.path || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("request=%s %s headers=%v", r.Method, r.URL.Path, r.Header)
				}
				var fields map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
					t.Error(err)
					return
				}
				if len(fields) != len(tc.keys) {
					t.Errorf("fields=%v", fields)
				}
				for _, key := range tc.keys {
					if v, ok := fields[key]; !ok || string(v) == "null" {
						t.Errorf("missing/null %s", key)
					}
				}
			}))
			defer srv.Close()
			repo, err := NewEupfHttpRepository(srv.URL, &config.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.send(repo); err != nil {
				t.Fatal(err)
			}
			select {
			case <-called:
			default:
				t.Fatal("request was not sent")
			}
		})
	}
}
