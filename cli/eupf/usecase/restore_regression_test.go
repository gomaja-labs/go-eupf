package usecase

import (
	"context"
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
	if err := storage.SaveUpfConfig(ctx, &domain.UpfConfig{LoggingLevel: "info"}); err != nil {
		t.Fatal(err)
	}
	backups, err := storage.BackupList(ctx)
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, err = %v", backups, err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "configuration rejected", http.StatusBadRequest)
	}))
	defer srv.Close()
	u := NewEupf(repository.NewEupfHttpRepository(srv.URL, cfg), storage, cfg)
	err = u.BackupRestore(ctx, "", backups[0].Name)
	if requests.Load() == 0 {
		t.Fatal("restore did not reach HTTP server")
	}
	if err == nil {
		t.Fatal("restore reported success after HTTP server rejected every update")
	}
}
