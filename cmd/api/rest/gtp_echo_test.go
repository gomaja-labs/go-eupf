package rest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
)

func TestGTPEchoRESTMinimumInterval(t *testing.T) {
	t.Chdir(t.TempDir())
	manager := core.NewGtpPathManager("127.0.0.1:0", time.Hour)
	defer manager.Stop()
	h := &ApiHandler{Cfg: &config.UpfConfig{}, GtpPathManager: manager}
	r := gin.New()
	r.POST("/gtp", h.editGTPPathConfig)
	for _, seconds := range []uint32{0, 1, 59, 60, 61} {
		out := httptest.NewRecorder()
		r.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "/gtp", strings.NewReader(fmt.Sprintf(`{"gtp_peer":[],"gtp_echo_interval":%d}`, seconds))))
		if seconds < 60 {
			if out.Code != 400 || !strings.Contains(out.Body.String(), "gtp_echo_interval") || !strings.Contains(out.Body.String(), "7.2.1") {
				t.Errorf("%d seconds: status=%d body=%s", seconds, out.Code, out.Body)
			}
		} else if out.Code != 200 {
			t.Errorf("%d seconds: status=%d body=%s", seconds, out.Code, out.Body)
		}
	}
}
