package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/config"
)

func TestRepositorySendsBearerToken(t *testing.T) {
	received := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
		if r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Errorf("missing bearer header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	repository, initErr := NewEupfHttpRepository(server.URL, &config.Config{ApiToken: "synthetic-token"})
	if initErr != nil {
		t.Fatal(initErr)
	}
	for _, base := range []string{"", server.URL} {
		if _, err := repository.GetUpfConfig(context.Background(), base); err != nil {
			t.Fatal(err)
		}
	}
	if received != 2 {
		t.Fatalf("requests=%d", received)
	}
}
