package domain_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/domain"
	"github.com/gomaja-labs/go-eupf/cmd/config"
)

func TestConfigurationJSONKeysMatchServer(t *testing.T) {
	server := reflect.TypeFor[config.UpfConfig]()
	client := reflect.TypeFor[domain.UpfConfig]()
	keys := map[string]reflect.Type{}
	for i := 0; i < client.NumField(); i++ {
		f := client.Field(i)
		keys[f.Tag.Get("json")] = f.Type
	}
	for i := 0; i < server.NumField(); i++ {
		f := server.Field(i)
		key := f.Tag.Get("json")
		if key == "" || key == "-" {
			continue
		}
		clientField, exists := client.FieldByName(f.Name)
		if !exists || clientField.Tag.Get("yaml") != f.Tag.Get("mapstructure") {
			t.Errorf("server key %s has incorrect CLI backup YAML key", key)
		}
		if keys[key] != f.Type {
			t.Errorf("server key %s (%v) missing or wrong type in CLI (%v)", key, f.Type, keys[key])
		}
	}
	wire, err := json.Marshal(config.UpfConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var cli domain.UpfConfig
	if err = json.Unmarshal(wire, &cli); err != nil {
		t.Fatal(err)
	}
	roundtrip, err := json.Marshal(cli)
	if err != nil {
		t.Fatal(err)
	}
	var original, restored map[string]json.RawMessage
	if err = json.Unmarshal(wire, &original); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(roundtrip, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, restored) {
		t.Errorf("configuration JSON keys changed during CLI round trip")
	}
}
