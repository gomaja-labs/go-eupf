package rest

// Configuration edit regressions. Synthetic values only.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
)

func postConfig(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	return out
}

func getConfig(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1:8080"
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	return out
}

// R2: validatedEdit copies the API-owned configuration with `next := *h.Cfg`.
// Slice fields keep their backing arrays and mapstructure v1.5.0 decodes into an
// existing non-nil slice element by element, so a REJECTED edit writes into the
// live configuration without holding cfgMu.
func TestRejectedEditPreservesLiveConfiguration(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := validEditConfig()
	cfg.GtpPeer = []string{"192.0.2.10:2152"}
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{}, nil, &cfg, nil, core.NewGtpPathManager("127.0.0.1:2152", time.Minute), nil)
	router := h.InitRoutes()

	out := postConfig(t, router, "/api/v1/config/gtp_path", `{"gtp_peer":["not a peer"],"gtp_echo_interval":60}`)
	t.Logf("invalid gtp_path edit: HTTP %d %s", out.Code, strings.TrimSpace(out.Body.String()))
	if out.Code != http.StatusBadRequest {
		t.Fatalf("invalid edit was not rejected: %d", out.Code)
	}
	var shown config.UpfConfig
	view := getConfig(t, router, "/api/v1/config")
	if err := json.Unmarshal(view.Body.Bytes(), &shown); err != nil {
		t.Fatal(err)
	}
	t.Logf("GET /config after the rejected edit: gtp_peer=%q", shown.GtpPeer)
	if !slices.Equal(shown.GtpPeer, []string{"192.0.2.10:2152"}) {
		t.Errorf("rejected edit changed the API-owned configuration: gtp_peer=%q", shown.GtpPeer)
	}
	next := postConfig(t, router, "/api/v1/config/logging_level", `{"logging_level":"debug"}`)
	t.Logf("unrelated valid logging_level edit afterwards: HTTP %d %s", next.Code, strings.TrimSpace(next.Body.String()))
	if next.Code != http.StatusOK {
		t.Errorf("an unrelated valid edit fails after one rejected edit: HTTP %d", next.Code)
	}
}

// Same mechanism on dataplane_ebpf: interface_name has no validation of its
// own, so a request rejected for xdp_attach_mode still rewrites interface_name.
func TestRejectedInterfaceEditPreservesLiveConfiguration(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := validEditConfig()
	cfg.InterfaceName = []string{"n3"}
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{}, nil, &cfg, nil, nil, nil)
	router := h.InitRoutes()
	out := postConfig(t, router, "/api/v1/config/dataplane_ebpf", `{"interface_name":["attacker0"],"xdp_attach_mode":"bogus"}`)
	t.Logf("invalid dataplane_ebpf edit: HTTP %d %s", out.Code, strings.TrimSpace(out.Body.String()))
	h.cfgMu.RLock()
	got := slices.Clone(h.Cfg.InterfaceName)
	h.cfgMu.RUnlock()
	t.Logf("API-owned interface_name after the rejected edit: %q", got)
	if out.Code != http.StatusBadRequest || !slices.Equal(got, []string{"n3"}) {
		t.Errorf("rejected edit changed interface_name to %q", got)
	}
}

// Accepted edits: the decoded slice keeps the old tail, so the API view and
// the runtime/file diverge (the file and GtpPathManager receive the submitted list).
func TestShorterListReplacesOldPeers(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := validEditConfig()
	cfg.GtpPeer = []string{"192.0.2.1:2152", "192.0.2.2:2152"}
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{}, nil, &cfg, nil, core.NewGtpPathManager("127.0.0.1:2152", time.Minute), nil)
	router := h.InitRoutes()
	out := postConfig(t, router, "/api/v1/config/gtp_path", `{"gtp_peer":["192.0.2.3:2152"],"gtp_echo_interval":60}`)
	h.cfgMu.RLock()
	got := slices.Clone(h.Cfg.GtpPeer)
	h.cfgMu.RUnlock()
	t.Logf("edit HTTP %d; API view gtp_peer=%q (submitted [192.0.2.3:2152])", out.Code, got)
	if out.Code != http.StatusOK || !slices.Equal(got, []string{"192.0.2.3:2152"}) {
		t.Errorf("API-owned configuration shows %q after submitting one peer", got)
	}
}

// Data race: validatedEdit writes the shared backing array without cfgMu while
// GET /config reads it under cfgMu.RLock. Run with -race.
func TestConcurrentConfigReadAndRejectedListEdits(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := validEditConfig()
	cfg.GtpPeer = []string{"192.0.2.10:2152"}
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{}, nil, &cfg, nil, core.NewGtpPathManager("127.0.0.1:2152", time.Minute), nil)
	router := h.InitRoutes()
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 200 {
			postConfig(t, router, "/api/v1/config/gtp_path", fmt.Sprintf(`{"gtp_peer":["bad peer %d"],"gtp_echo_interval":60}`, i))
		}
	})
	wg.Go(func() {
		for range 200 {
			getConfig(t, router, "/api/v1/config")
		}
	})
	wg.Wait()
}

// Same root cause: an accepted edit to an empty list leaves the old elements in
// the API-owned configuration (mapstructure keeps the existing non-nil slice).
func TestEmptyListRemovesPeers(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := validEditConfig()
	cfg.GtpPeer = []string{"192.0.2.1:2152", "192.0.2.2:2152"}
	gtp := core.NewGtpPathManager("127.0.0.1:2152", time.Minute)
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{}, nil, &cfg, nil, gtp, nil)
	out := postConfig(t, h.InitRoutes(), "/api/v1/config/gtp_path", `{"gtp_peer":[],"gtp_echo_interval":60}`)
	h.cfgMu.RLock()
	got := slices.Clone(h.Cfg.GtpPeer)
	h.cfgMu.RUnlock()
	t.Logf("POST gtp_peer=[]: HTTP %d; API view gtp_peer=%q", out.Code, got)
	if out.Code != http.StatusOK || len(got) != 0 {
		t.Errorf("API view still lists %q after the peers were removed", got)
	}
}
