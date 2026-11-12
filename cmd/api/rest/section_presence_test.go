package rest

import (
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"net/http"
	"testing"
)

// R2: PFCPTimersConfig.heartbeat_timeout lost binding:"required" (schemas.go:41)
// and the generated schema lists only association_setup_timeout as required.
// A request that omits it decodes 0, which disables heartbeat probing on every
// PFCP connection and is persisted.
func TestMissingHeartbeatTimeoutIsRejected(t *testing.T) {
	t.Chdir(t.TempDir())
	old := config.Conf
	config.Conf = config.UpfConfig{}
	t.Cleanup(func() { config.Conf = old })
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, nil, nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	cfg := validEditConfig()
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{core.N4PFCPKeyName: conn}, nil, &cfg, nil, nil, nil)
	out := postConfig(t, h.InitRoutes(), "/api/v1/config/pfcp_timers", `{"association_setup_timeout":10}`)
	h.cfgMu.RLock()
	hb := h.Cfg.HeartbeatTimeout
	h.cfgMu.RUnlock()
	t.Logf("POST {association_setup_timeout:10}: HTTP %d; heartbeat_timeout before=5 after=%d (0 disables probes, pfcp_runtime_options.go:13)", out.Code, hb)
	if out.Code != http.StatusBadRequest || hb != 5 {
		t.Error("omitting the optional heartbeat_timeout disabled heartbeat probing")
	}
}
