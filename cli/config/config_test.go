package config

import (
	"os"
	"strings"
	"testing"
)

func TestConfigEditDoesNotPersistEnvironmentToken(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("CLI_API_TOKEN", "synthetic-environment-token")
	cfg, err := NewConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.UpdateFile(map[string]interface{}{"eupf_addr": "http://192.0.2.1:8080/api/v1"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configFileName)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "synthetic-environment-token") || strings.Contains(string(data), "api_token") {
		t.Fatal("unrelated config edit persisted the environment token")
	}
	if cfg.ApiToken != "synthetic-environment-token" || cfg.EupfAddr != "http://192.0.2.1:8080/api/v1" {
		t.Fatalf("configuration did not retain effective settings")
	}
}
