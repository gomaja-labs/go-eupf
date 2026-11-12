package usecase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/config"
	"github.com/gomaja-labs/go-eupf/cli/domain"
	"github.com/gomaja-labs/go-eupf/cli/eupf/repository/file"
	repository "github.com/gomaja-labs/go-eupf/cli/eupf/repository/http"
)

func TestRestoreRejectsConnectionPresenceChanges(t *testing.T) {
	for _, key := range []string{"sxa_address", "sxb_address"} {
		for _, adding := range []bool{true, false} {
			name := key + "/remove"
			if adding {
				name = key + "/add"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				cfg := &config.Config{BackupPath: t.TempDir()}
				saved, current := &domain.UpfConfig{GtpEchoInterval: 60}, &domain.UpfConfig{GtpEchoInterval: 60}
				changed := current
				if adding {
					changed = saved
				}
				if key == "sxa_address" {
					changed.SxaLocalAddress = "127.0.0.2:8805"
				} else {
					changed.SxbLocalAddress = "127.0.0.3:8805"
				}
				storage := file.NewFileRepository(cfg)
				if err := storage.SaveUpfConfig(ctx, saved); err != nil {
					t.Fatal(err)
				}
				backups, err := storage.BackupList(ctx)
				if err != nil || len(backups) != 1 {
					t.Fatalf("backups=%v error=%v", backups, err)
				}
				var posts atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(current)
						return
					}
					posts.Add(1)
				}))
				defer srv.Close()
				repo, err := repository.NewEupfHttpRepository(srv.URL, cfg)
				if err != nil {
					t.Fatal(err)
				}
				u := NewEupf(repo, storage, cfg)
				err = u.BackupRestore(ctx, "", backups[0].Name)
				if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "restart") {
					t.Errorf("missing startup-only difference: %v", err)
				}
				if posts.Load() != 0 {
					t.Errorf("applied %d edits before rejecting the restore", posts.Load())
				}
			})
		}
	}
}
