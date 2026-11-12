package http

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/config"
)

func TestRepositoryVerifiesTLSWithCustomCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	repo, initErr := NewEupfHttpRepository(srv.URL, &config.Config{ApiCABundle: path})
	if initErr != nil {
		t.Fatal(initErr)
	}
	if _, err := repo.GetUpfConfig(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryRejectsUntrustedTLSAndInvalidCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	repo, err := NewEupfHttpRepository(srv.URL, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetUpfConfig(context.Background(), ""); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	path := filepath.Join(t.TempDir(), "not-ca.pem")
	if err := os.WriteFile(path, []byte("not a CA"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + ".missing"} {
		if _, err := NewEupfHttpRepository(srv.URL, &config.Config{ApiCABundle: file}); err == nil {
			t.Fatalf("accepted invalid CA bundle %q", file)
		}
	}
}
