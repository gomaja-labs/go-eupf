package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/config"
)

func TestGTPEchoCLIRejectsShortIntervals(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	defer server.Close()
	repo, initErr := NewEupfHttpRepository(server.URL, &config.Config{})
	if initErr != nil {
		t.Fatal(initErr)
	}
	for _, seconds := range []uint32{0, 1, 59} {
		err := repo.RestoreConfigGTPPath(context.Background(), nil, seconds, "")
		if err == nil || !strings.Contains(err.Error(), "gtp_echo_interval") || !strings.Contains(err.Error(), "7.2.1") {
			t.Errorf("%d seconds: %v", seconds, err)
		}
	}
	if calls != 0 {
		t.Errorf("invalid intervals sent %d HTTP requests", calls)
	}
	if err := repo.RestoreConfigGTPPath(context.Background(), nil, 60, ""); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("valid interval sent %d requests", calls)
	}
}
