//go:build linux

package rest

// REST N3/N9 interface edit in the
// default deployment where the advertised addresses derive from n3_address.

import (
	"encoding/binary"
	"net"
	"net/http"
	"testing"
	"time"

	kernel "github.com/cilium/ebpf"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

func TestInterfaceEditRefreshesDerivedAdvertisedAddresses(t *testing.T) {
	t.Chdir(t.TempDir())
	old := config.Conf
	config.Conf = config.UpfConfig{}
	t.Cleanup(func() { config.Conf = old })
	spec, err := ebpf.LoadIpEntrypoint()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Maps {
		m.Pinning = kernel.PinNone
	}
	bpf := ebpf.NewBpfObjects()
	if err := spec.LoadAndAssign(&bpf.IpEntrypointObjects, nil); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bpf.IpEntrypointObjects.Close() }()
	ip := func(s string) uint32 { return binary.LittleEndian.Uint32(net.ParseIP(s).To4()) }
	if err := bpf.GlobalConfig.Set(ebpf.IpEntrypointDataplaneConfig{N3Ipv4Address: ip("192.0.2.10"), N9Ipv4Address: ip("192.0.2.10")}); err != nil {
		t.Fatal(err)
	}
	// main.go:283-284: N4 advertises n3_adv_address / n9_adv_address, which
	// default to n3_address / n9_address (config.go:330-334).
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "192.0.2.10", "192.0.2.10", nil, testResources(t), nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	cfg := validEditConfig()
	cfg.N3Address, cfg.N9Address = "192.0.2.10", "192.0.2.10"
	cfg.N3AdvertisedAddress, cfg.N3AdvertisedAddress5G, cfg.N9AdvertisedAddress = "192.0.2.10", "192.0.2.10", "192.0.2.10"
	h := NewApiHandler(bpf, map[string]*core.PfcpConnection{core.N4PFCPKeyName: conn}, nil, &cfg, nil, core.NewGtpPathManager("192.0.2.10:2152", time.Minute), nil)
	out := postConfig(t, h.InitRoutes(), "/api/v1/config/dataplane_addresses", `{"n3_address":"192.0.2.20","n9_address":"192.0.2.20"}`)
	if out.Code != http.StatusOK {
		t.Fatalf("edit failed: %d %s", out.Code, out.Body)
	}
	var kernelCfg ebpf.IpEntrypointDataplaneConfig
	if err := bpf.GlobalConfig.Get(&kernelCfg); err != nil {
		t.Fatal(err)
	}
	n3 := make(net.IP, 4)
	binary.LittleEndian.PutUint32(n3, kernelCfg.N3Ipv4Address)
	t.Logf("after REST edit: XDP global N3=%s (GTP-U accepted only for this or N9, n3n6_entrypoint.c:553); N4 F-TEID address for new sessions=%s; API view n3_adv_address=%s",
		n3, conn.GetN3Addr(), h.Cfg.N3AdvertisedAddress)
	if h.Cfg.N3AdvertisedAddress != "192.0.2.20" || h.Cfg.N3AdvertisedAddress5G != "192.0.2.20" || h.Cfg.N9AdvertisedAddress != "192.0.2.20" {
		t.Errorf("API advertised addresses did not follow edit: %s/%s/%s", h.Cfg.N3AdvertisedAddress, h.Cfg.N3AdvertisedAddress5G, h.Cfg.N9AdvertisedAddress)
	}
	if conn.GetN9Addr() != "192.0.2.20" {
		t.Errorf("N9 runtime address=%s", conn.GetN9Addr())
	}
	if got := config.Conf.GetN3AdvertisedAddress5G(); !got.Equal(net.ParseIP("192.0.2.20")) {
		t.Errorf("5G runtime address=%s", got)
	}
	if conn.GetN3Addr() != n3.String() {
		t.Errorf("new sessions advertise %s but the datapath now accepts GTP-U only for %s (a restart with the persisted file advertises %s)",
			conn.GetN3Addr(), n3, n3)
	}
}
