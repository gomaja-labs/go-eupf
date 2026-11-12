package rest

import (
	"net/http/httptest"
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
func newReleaseRouter(h *ApiHandler) *gin.Engine {
	r := gin.New()
	r.POST("/release", h.pfcpAssociationRelease)
	return r
}
