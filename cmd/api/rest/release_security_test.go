package rest

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestReleaseDoesNotBlockWithoutReceiver(t *testing.T) {
	h := &ApiHandler{associationReleaseChan: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := newReleaseRouter(h)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/release", nil))
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("release handler blocks without receiver")
	}
	// Unblock the original implementation after the assertion.
	select {
	case <-h.associationReleaseChan:
	default:
	}
}
func TestCrossSiteRequestsCannotChangeState(t *testing.T) {
	t.Chdir(t.TempDir())
	h := &ApiHandler{Cfg: validEditConfigPtr(), associationReleaseChan: make(chan struct{}, 1)}
	r := h.InitRoutes()
	for _, tc := range []struct {
		method, path, host, content string
		status                      int
	}{
		{"GET", "/api/v1/pfcp_associations/release", "127.0.0.1", "", 404},
		{"HEAD", "/api/v1/pfcp_associations/release", "127.0.0.1", "", 404},
		{"POST", "/api/v1/config/logging_caller", "127.0.0.1", "text/plain", 415},
		{"POST", "/api/v1/config/logging_caller", "attacker.example", "application/json", 403},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"logging_caller":true}`))
		req.Host = tc.host
		req.Header.Set("Content-Type", tc.content)
		r.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("%s %s host=%s status=%d want=%d", tc.method, tc.path, tc.host, w.Code, tc.status)
		}
	}
	if len(h.associationReleaseChan) != 0 {
		t.Fatal("GET changed state")
	}
}

func newReleaseRouter(h *ApiHandler) *gin.Engine {
	r := gin.New()
	r.POST("/release", h.pfcpAssociationRelease)
	return r
}

func TestLoopbackManagementHosts(t *testing.T) {
	for _, host := range []string{"localhost", "localhost:8080", "LOCALHOST.", "127.0.0.2", "[::1]", "[::1]:8080"} {
		if !allowedManagementHost(host, "127.0.0.1") {
			t.Errorf("rejected %q", host)
		}
	}
	for _, host := range []string{"attacker.example", "localhost.attacker.example", "127.0.0.1.attacker.example", "192.0.2.1", ""} {
		if allowedManagementHost(host, "127.0.0.1") {
			t.Errorf("accepted %q", host)
		}
	}
}
