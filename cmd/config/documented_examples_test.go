package config

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestDocumentedDefaultConfigurationDecodes(t *testing.T) {
	doc, err := os.ReadFile("../../docs/Configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	_, example, ok := strings.Cut(string(doc), "### Default values YAML")
	if !ok {
		t.Fatal("default configuration example not found")
	}
	_, example, ok = strings.Cut(example, "```yaml\n")
	if !ok {
		t.Fatal("YAML example not found")
	}
	example, _, _ = strings.Cut(example, "```")
	initConfigFixture(t, example)
	var cfg UpfConfig
	if err := cfg.Unmarshal(); err != nil {
		t.Fatalf("documented configuration cannot be loaded: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("documented configuration is invalid: %v", err)
	}
}

func TestDocumentedInterfaceEnvironmentList(t *testing.T) {
	doc, err := os.ReadFile("../../docs/Configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	value := regexp.MustCompile(`(?m)^UPF_INTERFACE_NAME="([^"]+)"`).FindSubmatch(doc)
	if len(value) != 2 {
		t.Fatal("documented environment list not found")
	}
	t.Setenv("UPF_INTERFACE_NAME", string(value[1]))
	initConfigFixture(t, "{}\n")
	var cfg UpfConfig
	if err := cfg.Unmarshal(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.InterfaceName, []string{"eth0", "n6"}) {
		t.Errorf("documented environment list parsed as %q", cfg.InterfaceName)
	}
}
