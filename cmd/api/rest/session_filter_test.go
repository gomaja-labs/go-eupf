package rest

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInvalidSessionFilterReturnsSingleJSONResponse(t *testing.T) {
	h := &ApiHandler{}
	r := gin.New()
	r.GET("/sessions", h.listPfcpSessionsFiltered)
	for _, query := range []string{"ip=invalid", "teid=invalid"} {
		t.Run(query, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sessions?"+query, nil))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			decoder := json.NewDecoder(w.Body)
			var value any
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			if err := decoder.Decode(&value); err != io.EOF {
				t.Errorf("extra response after error: %v", err)
			}
		})
	}
}
