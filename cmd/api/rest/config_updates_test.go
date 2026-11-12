package rest

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/rs/zerolog"
)

func TestConfigurationEditsDoNotMutateStartupConfig(t *testing.T) {
 previousLevel:=zerolog.GlobalLevel();defer zerolog.SetGlobalLevel(previousLevel)
	t.Chdir(t.TempDir())
	startup := config.UpfConfig{LoggingLevel: "info", InterfaceName: []string{"original"}}
	h := NewApiHandler(nil, nil, nil, &startup, nil, nil, nil)
	h.Cfg.InterfaceName[0] = "api-owned"
	router := h.InitRoutes()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 40 {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/config/logging_level", strings.NewReader(`{"logging_level":"warn"}`))
			out := httptest.NewRecorder()
			router.ServeHTTP(out, req)
			if out.Code != 200 {
				t.Errorf("edit status=%d", out.Code)
			}
		}
	})
	wg.Go(func() {
		for range 40 {
			out := httptest.NewRecorder()
			router.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
			if out.Code != 200 {
				t.Errorf("read status=%d", out.Code)
			}
			if startup.LoggingLevel != "info" || startup.InterfaceName[0] != "original" {
				t.Error("runtime edit mutated shared startup config")
			}
		}
	})
	wg.Wait()
}

func TestConfigurationPersistenceFailureIsReported(t *testing.T) {
	t.Chdir(t.TempDir())
	h := &ApiHandler{Cfg: &config.UpfConfig{}}
	router := gin.New()
	router.POST("/logging", h.editLoggingCallerConfig)
	// The fallback config path cannot be written when occupied by a directory.
	if err := os.Mkdir("config.yml", 0700); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	router.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "/logging", strings.NewReader(`{"logging_caller":true}`)))
	if out.Code != 500 || !strings.Contains(out.Body.String(), "runtime edit applied") {
		t.Fatalf("status=%d body=%s", out.Code, out.Body)
	}
}

func TestChangingAttachModeRequiresRemovingActiveInterfaces(t *testing.T) {
	links := []link.Link{nil}
	h := &ApiHandler{Cfg: &config.UpfConfig{XDPAttachMode: "generic"}, Links: &links}
	router := gin.New()
	router.POST("/ebpf", h.editDataPlaneConfig)
	out := httptest.NewRecorder()
	router.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "/ebpf", strings.NewReader(`{"interface_name":["lo"],"xdp_attach_mode":"native"}`)))
	if out.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", out.Code, out.Body)
	}
}
