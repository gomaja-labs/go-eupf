package rest

// Regression coverage for configuration validity and transactional endpoint edits.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
)

func validEditConfig() config.UpfConfig {
	// Values equal to the documented startup defaults (cmd/config/config.go flags).
	return config.UpfConfig{
		ApiAddress: "127.0.0.1:8080", LoggingLevel: "info", XDPAttachMode: "generic",
		PfcpAddress: "127.0.0.1:8805", PfcpNodeId: "127.0.0.1", MetricsAddress: ":9090",
		N3Address: "127.0.0.1", N9Address: "127.0.0.1", N3AdvertisedAddress: "127.0.0.1",
		N3AdvertisedAddress5G: "127.0.0.1", N9AdvertisedAddress: "127.0.0.1",
		UEIPPool: "10.60.0.0/24", Ip6RaPrefix: "2a03:d000:29a0:509::/64", MaxSessions: 65535,
		TraceMaxDumpFiles: 10, TraceMaxDumpSize: 10 << 20, TraceMaxDumpPackets: 100000,
		HeartbeatTimeout: 5, HeartbeatRetries: 3, HeartbeatInterval: 5,
		PfcpRequestTimeout: 5, PfcpRequestRetries: 3, PfcpResponseRetention: 60,
		AssociationSetupTimeout: 5, GtpEchoInterval: 60,
	}
}

// Every accepted edit of every REST binding is persisted, and the persisted
// values must still pass the validation config.Init applies at the next start.
func TestEditsKeepStartupValidity(t *testing.T) {
	baseline := validEditConfig()
	if err := baseline.Validate(); err != nil {
		t.Fatalf("baseline invalid: %v", err)
	}
	old := config.Conf
	config.Conf = config.UpfConfig{}
	t.Cleanup(func() { config.Conf = old })
	for _, tc := range []struct{ path, body string }{
		{"/api/v1/config/pfcp_timers", `{"association_setup_timeout":5,"heartbeat_timeout":16}`},
		{"/api/v1/config/gtp_path", `{"gtp_peer":["192.0.2.1"],"gtp_echo_interval":60}`},
		{"/api/v1/config/gtp_path", `{"gtp_peer":["192.0.2.1:2152"],"gtp_echo_interval":2000000}`},
		{"/api/v1/config/pfcp_n4", `{"pfcp_address":"127.0.0.1:0","pfcp_node_id":"127.0.0.1","pfcp_remote_node":[]}`},
	} {
		t.Run(tc.body, func(t *testing.T) {
			t.Chdir(t.TempDir())
			conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, testResources(t), nil, nil, core.DefaultProfile{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(conn.Close)
			cfg := validEditConfig()
			cfg.PfcpAddress = conn.GetLocalAddr()
			h := NewApiHandler(nil, map[string]*core.PfcpConnection{core.N4PFCPKeyName: conn}, nil, &cfg, nil,
				core.NewGtpPathManager("127.0.0.1:2152", time.Minute), nil)
			out := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Host = "127.0.0.1:8080"
			h.InitRoutes().ServeHTTP(out, req)
			if out.Code != 400 {
				t.Errorf("invalid edit status=%d body=%s", out.Code, out.Body)
			}
			h.cfgMu.RLock()
			next := *h.Cfg
			h.cfgMu.RUnlock()
			if err := next.Validate(); out.Code == http.StatusOK && err != nil {
				t.Errorf("HTTP 200 and persisted, but the next start fails validation: %v", err)
			}
		})
	}
}

// An accepted runtime edit must not persist a configuration that the startup
// validator rejects (the next start would exit in config.Init).
func TestTimerEditKeepsStartupValidity(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := validEditConfig()
	if err := cfg.ValidatePFCP(); err != nil {
		t.Fatalf("baseline invalid: %v", err)
	}
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{}, nil, &cfg, nil, nil, nil)
	router := h.InitRoutes()
	for _, timeout := range []int{16, 3601} {
		out := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/config/pfcp_timers", strings.NewReader(`{"association_setup_timeout":5,"heartbeat_timeout":`+strconv.Itoa(timeout)+`}`))
		req.Host = "127.0.0.1:8080"
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(out, req)
		if out.Code != http.StatusBadRequest {
			t.Errorf("invalid timer status=%d body=%s", out.Code, out.Body)
		}
		h.cfgMu.RLock()
		err := h.Cfg.ValidatePFCP()
		h.cfgMu.RUnlock()
		if out.Code == http.StatusOK && err != nil {
			t.Errorf("heartbeat_timeout=%d: HTTP 200 and persisted, but the startup validator now fails: %v", timeout, err)
		}
	}
}

// An edit that fails must not leave the PFCP endpoint half-applied.
func TestPFCPEndpointEditIsAtomic(t *testing.T) {
	t.Chdir(t.TempDir())
	old := config.Conf
	config.Conf = config.UpfConfig{}
	t.Cleanup(func() { config.Conf = old })
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, testResources(t), nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	before := conn.GetLocalAddr()
	free, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	target := free.LocalAddr().String()
	_ = free.Close()
	cfg := validEditConfig()
	cfg.PfcpAddress = before
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{core.N4PFCPKeyName: conn}, nil, &cfg, nil, nil, nil)
	gin.SetMode(gin.TestMode)
	router := h.InitRoutes()
	out := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/pfcp_n4", strings.NewReader(`{"pfcp_address":"`+target+`","pfcp_node_id":"127.0.0.1","pfcp_remote_node":["bad host name"]}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest {
		t.Errorf("invalid endpoint status=%d body=%s", out.Code, out.Body)
	}
	h.cfgMu.RLock()
	view := h.Cfg.PfcpAddress
	h.cfgMu.RUnlock()
	if out.Code != http.StatusOK && conn.GetLocalAddr() != before {
		t.Errorf("edit failed (HTTP %d: %s) but the PFCP socket moved %s -> %s; API view still %s and nothing persisted",
			out.Code, strings.TrimSpace(out.Body.String()), before, conn.GetLocalAddr(), view)
	}
}

func validEditConfigPtr() *config.UpfConfig { c := validEditConfig(); return &c }
