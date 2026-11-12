package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func TestAdvertisedAddressProvenanceSurvivesEditAndReload(t *testing.T) {
	for _, source := range []string{"file", "flag", "env"} {
		for mask := range 8 {
			t.Run(fmt.Sprintf("%s/%d", source, mask), func(t *testing.T) {
				keys := []string{"n3_adv_address", "n3_adv_address_5g", "n9_adv_address"}
				flags := []string{"n3advaddr", "n3advaddr5g", "n9advaddr"}
				old := []string{"192.0.2.10", "192.0.2.10", "192.0.2.11"}
				body := "n3_address: 192.0.2.10\nn9_address: 192.0.2.11\n"
				if source == "file" {
					for i, key := range keys {
						if mask&(1<<i) != 0 {
							body += key + ": " + old[i] + "\n"
						}
					}
				}
				path := initConfigFixture(t, body)
				for i, key := range keys {
					if mask&(1<<i) != 0 {
						switch source {
						case "flag":
							if err := pflag.Set(flags[i], old[i]); err != nil {
								t.Fatal(err)
							}
						case "env":
							t.Setenv("UPF_"+strings.ToUpper(key), old[i])
						}
					}
				}
				var cfg UpfConfig
				if err := cfg.Unmarshal(); err != nil {
					t.Fatal(err)
				}
				cfg.N3Address, cfg.N9Address = "192.0.2.20", "192.0.2.21"
				cfg.RefreshDerivedAdvertisedAddresses()
				want := []string{"192.0.2.20", "192.0.2.20", "192.0.2.21"}
				for i := range want {
					if mask&(1<<i) != 0 {
						want[i] = old[i]
					}
				}
				got := []string{cfg.N3AdvertisedAddress, cfg.N3AdvertisedAddress5G, cfg.N9AdvertisedAddress}
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("%s=%s want=%s", keys[i], got[i], want[i])
					}
				}
				if err := cfg.UpdateFile(map[string]interface{}{"n3_address": cfg.N3Address, "n9_address": cfg.N9Address}); err != nil {
					t.Fatal(err)
				}
				commonConfigV = viper.New()
				if err := initCommonConfig(); err != nil {
					t.Fatal(err)
				}
				var restarted UpfConfig
				if err := restarted.Unmarshal(); err != nil {
					t.Fatal(err)
				}
				if restarted.N3AdvertisedAddress != want[0] || restarted.N3AdvertisedAddress5G != want[1] || restarted.N9AdvertisedAddress != want[2] {
					t.Fatalf("runtime=%v restart=%s/%s/%s file=%s", got, restarted.N3AdvertisedAddress, restarted.N3AdvertisedAddress5G, restarted.N9AdvertisedAddress, path)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for i, key := range keys {
					if source != "file" || mask&(1<<i) == 0 {
						if strings.Contains(string(raw), key+":") {
							t.Fatalf("derived/override-only %s was frozen in the file", key)
						}
					}
				}
			})
		}
	}
}

func TestEmptyAdvertisedAddressesDerive(t *testing.T) {
	initConfigFixture(t, "n3_address: 192.0.2.10\nn9_address: 192.0.2.11\nn3_adv_address: ''\nn3_adv_address_5g: ''\nn9_adv_address: ''\n")
	var c UpfConfig
	if err := c.Unmarshal(); err != nil {
		t.Fatal(err)
	}
	if c.N3AdvertisedAddress != "192.0.2.10" || c.N3AdvertisedAddress5G != "192.0.2.10" || c.N9AdvertisedAddress != "192.0.2.11" {
		t.Fatal("empty advertised addresses did not derive")
	}
}

func TestRuntime5GAddressConcurrentSnapshots(t *testing.T) {
	c := validLimitsConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 500 {
			c.SetRuntimeN3AdvertisedAddress5G(net.ParseIP("192.0.2.20"))
		}
	})
	wg.Go(func() {
		for range 500 {
			addr := c.GetN3AdvertisedAddress5G()
			if !addr.Equal(net.ParseIP("192.0.2.1")) && !addr.Equal(net.ParseIP("192.0.2.20")) {
				t.Errorf("invalid snapshot %s", addr)
			}
			snapshot := c.Clone()
			if snapshot.GetN3AdvertisedAddress5G() == nil {
				t.Error("lost parsed snapshot")
			}
		}
	})
	wg.Wait()
	ip := c.GetN3AdvertisedAddress5G()
	ip[0] ^= 0xff
	if c.GetN3AdvertisedAddress5G().Equal(ip) {
		t.Fatal("getter exposes mutable runtime address")
	}
}
