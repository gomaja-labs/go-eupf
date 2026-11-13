package delivery

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/config"
	repository "github.com/gomaja-labs/go-eupf/cli/eupf/repository/http"
	"github.com/gomaja-labs/go-eupf/cli/eupf/usecase"
	serverconfig "github.com/gomaja-labs/go-eupf/cmd/config"
)

func TestConfigShowPreservesServerFields(t *testing.T) {
	serverConfig := serverconfig.UpfConfig{PfcpPeerAllowList: []string{"192.0.2.0/24"}, PfcpRequestTimeout: 2, PfcpRequestRetries: 4, PfcpResponseRetention: 30, PfcpMaxReplayEntries: 128, PfcpMaxOriginatedRequests: 64, PfcpReplayMemoryMiB: 32, ResourceReuseDelay: 60, PfcpMaxAssociations: 16, HeartbeatFailureGrace: 15}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(serverConfig)
	}))
	defer server.Close()
	cfg := &config.Config{}
	repo, initErr := repository.NewEupfHttpRepository(server.URL, cfg)
	if initErr != nil {
		t.Fatal(initErr)
	}
	cli := NewCLI(usecase.NewEupf(repo, nil, cfg))
	var output bytes.Buffer
	cli.Root.SetOut(&output)
	cli.Root.SetArgs([]string{"show"})
	if err := cli.Root.Execute(); err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	if err = json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatal("config show omitted or changed server configuration fields")
	}
}
