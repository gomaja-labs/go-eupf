package rest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/config"
)

func TestManagementAuthenticationAndCORS(t *testing.T) {
	h := &ApiHandler{Cfg: &config.UpfConfig{ApiToken: "test-token", ApiAllowedOrigins: []string{"https://console.example"}}, associationReleaseChan: make(chan struct{}, 8)}
	srv := httptest.NewServer(h.InitRoutes())
	defer srv.Close()
	for _, tc := range []struct {
		path, token, origin string
		status              int
		allowed             string
	}{
		{"/api/v1/pfcp_associations/release", "", "", 401, ""},
		{"/api/v1/pfcp_associations/release", "Bearer wrong", "", 401, ""},
		{"/api/v1/pfcp_associations/release", "test-token", "", 401, ""},
		{"/api/v1/pfcp_associations/release", "Bearer test-token", "", 204, ""},
		{"/api/v1/health", "", "", 200, ""},
		{"/swagger/index.html", "", "", 401, ""},
		{"/api/v1/config", "Bearer test-token", "https://console.example", 200, "https://console.example"},
		{"/api/v1/config", "bearer test-token", "", 200, ""},
		{"/api/v1/config", "Bearer   test-token", "", 200, ""},
		{"/api/v1/config", "Bearer test-token", "https://evil.example", 403, ""},
	} {
		method := http.MethodGet
		if strings.HasSuffix(tc.path, "/release") {
			method = http.MethodPost
		}
		req, err := http.NewRequest(method, srv.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if tc.token != "" {
			req.Header.Set("Authorization", tc.token)
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if strings.Contains(string(body), "test-token") {
			t.Errorf("response discloses API token")
		}
		if resp.StatusCode != tc.status {
			t.Errorf("%s status=%d want=%d", tc.path, resp.StatusCode, tc.status)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != tc.allowed {
			t.Errorf("CORS header=%q want=%q", got, tc.allowed)
		}
	}
	if len(h.associationReleaseChan) != 1 {
		t.Fatalf("release signals=%d", len(h.associationReleaseChan))
	}
}

func TestManagementDefaultHasNoCORS(t *testing.T) {
	h := &ApiHandler{Cfg: &config.UpfConfig{}}
	r := h.InitRoutes()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://console.example")
	r.ServeHTTP(w, req)
	if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("status=%d CORS=%q", w.Code, w.Header().Get("Access-Control-Allow-Origin"))
	}
	if mode := gin.Mode(); mode != gin.ReleaseMode {
		t.Fatalf("mode=%s", mode)
	}
}
