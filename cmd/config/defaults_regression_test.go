package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func initConfigFixture(t *testing.T, data string) string {
	t.Helper()
	t.Chdir(t.TempDir())
	path := filepath.Join(".", "custom.yml")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	oldFlags, oldArgs, oldV := pflag.CommandLine, os.Args, commonConfigV
	t.Cleanup(func() { pflag.CommandLine, os.Args, commonConfigV = oldFlags, oldArgs, oldV })
	pflag.CommandLine = pflag.NewFlagSet("config-test", pflag.ContinueOnError)
	os.Args = []string{"config-test", "--config", path}
	commonConfigV = viper.New()
	defineFlags()
	initCommonConfig()
	return path
}

func TestAdvertisedAddressDefaultsFollowConfiguredAddress(t *testing.T) {
	initConfigFixture(t, "n3_address: 192.0.2.10\nn9_address: 192.0.2.11\n")
	var c UpfConfig
	if err := c.Unmarshal(); err != nil {
		t.Fatal(err)
	}
	if c.N3AdvertisedAddress != "192.0.2.10" || c.N3AdvertisedAddress5G != "192.0.2.10" || c.N9AdvertisedAddress != "192.0.2.11" {
		t.Errorf("derived addresses = %s, %s, %s", c.N3AdvertisedAddress, c.N3AdvertisedAddress5G, c.N9AdvertisedAddress)
	}
}

func TestConfigUpdateUsesSelectedConfigFile(t *testing.T) {
	path := initConfigFixture(t, "logging_level: info\n")
	var c UpfConfig
	if err := c.UpdateFile(map[string]interface{}{"logging_level": "debug"}); err != nil {
		t.Fatal(err)
	}
	saved := viper.New()
	saved.SetConfigFile(path)
	if err := saved.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	if got := saved.GetString("logging_level"); got != "debug" {
		t.Errorf("selected file still contains %q, want debug", got)
	}
}
