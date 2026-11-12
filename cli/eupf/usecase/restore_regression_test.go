package usecase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/config"
	"github.com/gomaja-labs/go-eupf/cli/domain"
	"github.com/gomaja-labs/go-eupf/cli/eupf/repository/file"
	repository "github.com/gomaja-labs/go-eupf/cli/eupf/repository/http"
)

func TestBackupRestoreReportsHTTPFailures(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{BackupPath: t.TempDir()}
	storage := file.NewFileRepository(cfg)
	if err := storage.SaveUpfConfig(ctx, &domain.UpfConfig{LoggingLevel: "info", GtpEchoInterval: 60}); err != nil {
		t.Fatal(err)
	}
	backups, err := storage.BackupList(ctx)
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, err = %v", backups, err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(domain.UpfConfig{LoggingLevel: "info", GtpEchoInterval: 60})
			return
		}
		requests.Add(1)
		http.Error(w, "configuration rejected", http.StatusBadRequest)
	}))
	defer srv.Close()
	u := NewEupf(repository.NewEupfHttpRepository(srv.URL, cfg), storage, cfg)
	err = u.BackupRestore(ctx, "", backups[0].Name)
	if requests.Load() != 7 {
		t.Fatalf("restore reached %d sections, want 7", requests.Load())
	}
	if err == nil {
		t.Fatal("restore reported success after HTTP server rejected every update")
	}
}

func TestBackupRestoreSkipsDisabledConnections(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{BackupPath: t.TempDir()}
	saved := &domain.UpfConfig{LoggingLevel: "info", GtpEchoInterval: 60}
	storage := file.NewFileRepository(cfg)
	if err := storage.SaveUpfConfig(ctx, saved); err != nil {
		t.Fatal(err)
	}
	backups, err := storage.BackupList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if r.URL.Path == "/config/pfcp_sxa" || r.URL.Path == "/config/pfcp_sxb" {
			t.Error("restore posted a disabled connection")
			http.Error(w, "disabled", 400)
		}
	}))
	defer srv.Close()
	u := NewEupf(repository.NewEupfHttpRepository(srv.URL, cfg), storage, cfg)
	if err := u.BackupRestore(ctx, "", backups[0].Name); err != nil {
		t.Fatal(err)
	}
}
