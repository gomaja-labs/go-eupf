package usecase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/gomaja-labs/go-eupf/cli/config"
	"github.com/gomaja-labs/go-eupf/cli/domain"
	"github.com/gomaja-labs/go-eupf/cli/eupf/repository/file"
	repository "github.com/gomaja-labs/go-eupf/cli/eupf/repository/http"
)

func TestRestoreRejectsChangedStartupPolicyBeforeEdits(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{BackupPath: t.TempDir()}
	storage := file.NewFileRepository(cfg)
	saved := &domain.UpfConfig{PfcpPeerAllowList: []string{"192.0.2.0/24"}, PfcpRequestTimeout: 2, PfcpRequestRetries: 4, PfcpResponseRetention: 30, PfcpMaxReplayEntries: 128, PfcpMaxOriginatedRequests: 64, PfcpReplayMemoryMiB: 32, ResourceReuseDelay: 60, PfcpMaxAssociations: 16, HeartbeatFailureGrace: 15, GtpEchoInterval: 60}
	if err := storage.SaveUpfConfig(ctx, saved); err != nil {
		t.Fatal(err)
	}
	backups, err := storage.BackupList(ctx)
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups=%v err=%v", backups, err)
	}
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(domain.UpfConfig{})
			return
		}
		posts++
		w.WriteHeader(200)
	}))
	defer srv.Close()
	repo, initErr := repository.NewEupfHttpRepository(srv.URL, cfg)
	if initErr != nil {
		t.Fatal(initErr)
	}
	u := NewEupf(repo, storage, cfg)
	err = u.BackupRestore(ctx, "", backups[0].Name)
	for _, key := range []string{"pfcp_peer_allow_list", "pfcp_request_timeout", "pfcp_request_retries", "pfcp_response_retention", "pfcp_max_replay_entries", "pfcp_max_originated_requests", "pfcp_replay_memory_mib", "pfcp_max_associations", "heartbeat_failure_grace", "resource_reuse_delay"} {
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("missing restart requirement for %s: %v", key, err)
		}
	}
	if posts != 0 {
		t.Errorf("restore partially applied %d edits before reporting startup-only differences", posts)
	}
	restored, err := storage.ReadUpfConfig(ctx, backups[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := yaml.Marshal(saved)
	b, _ := yaml.Marshal(restored)
	if string(a) != string(b) {
		t.Fatal("backup round trip lost configuration values")
	}
}
