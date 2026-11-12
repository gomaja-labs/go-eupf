package config

import (
	"os"
	"strings"
	"testing"
)

func TestDataplaneStartupDefaults(t *testing.T) {
	initConfigFixture(t, "{}\n")
	var c UpfConfig
	if err := c.Unmarshal(); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.InterfaceName) != 0 || c.XDPAttachMode != "generic" {
		t.Fatalf("attachment defaults: %v %s", c.InterfaceName, c.XDPAttachMode)
	}
	if c.N3Address != "127.0.0.1" || c.N9Address != c.N3Address {
		t.Fatalf("local address defaults: %s/%s", c.N3Address, c.N9Address)
	}
	if !c.TraceIn || !c.TraceOut || c.TraceBlocked || c.IP6RaSupport {
		t.Fatalf("XDP switch defaults: in=%v out=%v blocked=%v RA=%v", c.TraceIn, c.TraceOut, c.TraceBlocked, c.IP6RaSupport)
	}
	if c.Ip6RaPrefix != "2a03:d000:29a0:509::/64" {
		t.Fatalf("RA prefix default: %s", c.Ip6RaPrefix)
	}
	if len(c.GtpPeer) != 0 || c.GtpEchoInterval != 60 || c.TraceMaxDumpFiles != 10 || c.TraceMaxDumpSize != 10485760 || c.TraceMaxDumpPackets != 100000 {
		t.Fatal("GTP path or dump defaults differ from the documented values")
	}
	if c.S1UAddress != "127.0.0.1" || c.S5S8Address != "127.0.0.1" || c.PAAddress != "127.0.0.1" {
		t.Fatalf("Sxa/Sxb defaults: %s/%s/%s", c.S1UAddress, c.S5S8Address, c.PAAddress)
	}
}

func TestDataplaneDocumentedValueValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*UpfConfig)
		valid bool
	}{
		{"generic", func(c *UpfConfig) { c.XDPAttachMode = "generic" }, true},
		{"native", func(c *UpfConfig) { c.XDPAttachMode = "native" }, true},
		{"offload", func(c *UpfConfig) { c.XDPAttachMode = "offload" }, true},
		{"unknown mode", func(c *UpfConfig) { c.XDPAttachMode = "auto" }, false},
		{"N3 hostname", func(c *UpfConfig) { c.N3Address = "upf.example" }, false},
		{"N9 IPv6", func(c *UpfConfig) { c.N9Address = "2001:db8::1" }, false},
		{"advertised N3 hostname", func(c *UpfConfig) { c.N3AdvertisedAddress = "upf.example" }, false},
		{"advertised 5G IPv6", func(c *UpfConfig) { c.N3AdvertisedAddress5G = "2001:db8::1" }, false},
		{"advertised N9 hostname", func(c *UpfConfig) { c.N9AdvertisedAddress = "upf.example" }, false},
		{"S1U IPv6", func(c *UpfConfig) { c.S1UAddress = "2001:db8::1" }, false},
		{"S5S8 hostname", func(c *UpfConfig) { c.S5S8Address = "upf.example" }, false},
		{"PA IPv6", func(c *UpfConfig) { c.PAAddress = "2001:db8::1" }, false},
		{"empty Sxa Sxb", func(c *UpfConfig) { c.S1UAddress, c.S5S8Address, c.PAAddress = "", "", "" }, true},
		{"IPv6 prefix 48", func(c *UpfConfig) { c.Ip6RaPrefix = "2001:db8::/48" }, true},
		{"IPv6 prefix 64 enabled", func(c *UpfConfig) { c.IP6RaSupport = true; c.Ip6RaPrefix = "2001:db8::/64" }, true},
		{"IPv4 prefix disabled", func(c *UpfConfig) { c.IP6RaSupport = false; c.Ip6RaPrefix = "192.0.2.0/24" }, false},
		{"missing prefix disabled", func(c *UpfConfig) { c.IP6RaSupport = false; c.Ip6RaPrefix = "" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validLimitsConfig()
			tc.edit(&c)
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestAdvertisedAddressDocumentationExample(t *testing.T) {
	doc, err := os.ReadFile("../../docs/advertised-addresses.md")
	if err != nil {
		t.Fatal(err)
	}
	_, example, ok := strings.Cut(string(doc), "```yaml\n")
	if !ok {
		t.Fatal("advertised-address YAML example missing")
	}
	example, _, _ = strings.Cut(example, "```")
	initConfigFixture(t, example)
	var c UpfConfig
	if err := c.Unmarshal(); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.N3Address, c.N9Address = "192.0.2.20", "192.0.2.21"
	c.RefreshDerivedAdvertisedAddresses()
	if c.N3AdvertisedAddress != "198.51.100.10" || c.N3AdvertisedAddress5G != "198.51.100.10" || c.N9AdvertisedAddress != "198.51.100.11" {
		t.Fatalf("explicit example addresses changed: %s/%s/%s", c.N3AdvertisedAddress, c.N3AdvertisedAddress5G, c.N9AdvertisedAddress)
	}
}
