package rest

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/rs/zerolog"
)

func TestConfigReadDuringLoggingLevelUpdate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldConf, oldLevel := config.Conf, zerolog.GlobalLevel()
	defer func() { config.Conf = oldConf; zerolog.SetGlobalLevel(oldLevel) }()
	h := &ApiHandler{Cfg: &config.Conf}
	r := gin.New()
	r.GET("/config", h.displayConfig)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for range 256 {
			if err := core.UpdateLogLevel("info"); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Go(func() {
		<-start
		for range 256 {
			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/config", nil))
		}
	})
	close(start)
	wg.Wait()
}
