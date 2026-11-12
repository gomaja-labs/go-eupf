package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/core"
)

func TestInvalidPFCPTimersDoNotReplaceTicker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, body := range []string{"{", "{}", `{"association_setup_timeout":0,"heartbeat_timeout":5}`} {
		t.Run(body, func(t *testing.T) {
			original := time.NewTicker(time.Hour)
			defer original.Stop()
			conn := &core.PfcpConnection{AssociationSetupTicker: original}
			h := &ApiHandler{pfcpSrv: map[string]*core.PfcpConnection{core.N4PFCPKeyName: conn}}
			r := gin.New()
			r.POST("/config/pfcp_timers", h.editPFCPTimersConfig)
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("invalid request panicked: %v", p)
				}
				if conn.AssociationSetupTicker != original {
					conn.AssociationSetupTicker.Stop()
					t.Error("invalid request changed the running ticker")
				}
			}()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/config/pfcp_timers", strings.NewReader(body)))
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
		})
	}
}
