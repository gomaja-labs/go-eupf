package rest

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/core"
)

func TestEveryConfigSectionRequiresEveryField(t *testing.T) {
	sections := map[string]string{
		"logging_level":       `{"logging_level":"info"}`,
		"logging_caller":      `{"logging_caller":false}`,
		"dataplane_ebpf":      `{"interface_name":[],"xdp_attach_mode":"generic"}`,
		"dataplane_addresses": `{"n3_address":"192.0.2.1","n9_address":"192.0.2.2"}`,
		"pfcp_n4":             `{"pfcp_address":"127.0.0.1:8805","pfcp_node_id":"127.0.0.1","pfcp_remote_node":[]}`,
		"pfcp_sxa":            `{"sxa_address":"127.0.0.1:8805","sxa_node_id":"127.0.0.1","sxa_remote_node":[]}`,
		"pfcp_sxb":            `{"sxb_address":"127.0.0.1:8805","sxb_node_id":"127.0.0.1","sxb_remote_node":[]}`,
		"pfcp_timers":         `{"association_setup_timeout":5,"heartbeat_timeout":0}`,
		"gtp_path":            `{"gtp_peer":[],"gtp_echo_interval":60}`,
	}
	for section, body := range sections {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &fields); err != nil {
			t.Fatal(err)
		}
		for field := range fields {
			for _, null := range []bool{false, true} {
				t.Run(section+"/"+field+"/null="+map[bool]string{true: "true", false: "false"}[null], func(t *testing.T) {
					t.Chdir(t.TempDir())
					cfg := validEditConfig()
					h := NewApiHandler(nil, map[string]*core.PfcpConnection{}, nil, &cfg, nil, nil, nil)
					edit := make(map[string]json.RawMessage)
					for k, v := range fields {
						if k != field {
							edit[k] = v
						}
					}
					if null {
						edit[field] = json.RawMessage("null")
					}
					data, err := json.Marshal(edit)
					if err != nil {
						t.Fatal(err)
					}
					out := postConfig(t, h.InitRoutes(), "/api/v1/config/"+section, string(data))
					if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), field) {
						t.Fatalf("missing/null %s: status=%d body=%s", field, out.Code, out.Body)
					}
				})
			}
		}
	}
}

func TestExplicitZeroAndFalseConfigValues(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := validEditConfig()
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{}, nil, &cfg, nil, nil, nil)
	router := h.InitRoutes()
	for section, body := range map[string]string{
		"pfcp_timers":    `{"association_setup_timeout":5,"heartbeat_timeout":0}`,
		"logging_caller": `{"logging_caller":false}`,
	} {
		out := postConfig(t, router, "/api/v1/config/"+section, body)
		if out.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", section, out.Code, out.Body)
		}
	}
	if h.Cfg.HeartbeatTimeout != 0 || h.Cfg.LoggingCaller {
		t.Fatal("explicit zero/false not applied")
	}
}
