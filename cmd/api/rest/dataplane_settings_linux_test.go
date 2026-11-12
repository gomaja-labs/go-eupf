//go:build linux

package rest

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kernel "github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

func TestAddressEditPreservesOtherDataplaneSettings(t *testing.T) {
	t.Chdir(t.TempDir())
	old := config.Conf
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
	initial := ebpf.IpEntrypointDataplaneConfig{
		TraceIn: 1, TraceOut: 1, TraceBlocked: 1, Ip6RaSupport: 1, Ip6RaPrefixLength: 64,
		N3Ipv4Address: binary.LittleEndian.Uint32(net.ParseIP("192.0.2.1").To4()),
		N9Ipv4Address: binary.LittleEndian.Uint32(net.ParseIP("192.0.2.2").To4()),
	}
	copy(initial.Ip6RaPrefix[:], net.ParseIP("2001:db8:1234::").To16())
	if err := bpf.GlobalConfig.Set(initial); err != nil {
		t.Fatal(err)
	}
	h := &ApiHandler{
		BpfObjects: bpf, Cfg: validEditConfigPtr(),
		pfcpSrv:        map[string]*core.PfcpConnection{},
		GtpPathManager: core.NewGtpPathManager("192.0.2.1:2152", time.Second),
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/addresses", h.editDataPlaneAddressesConfig)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/addresses", strings.NewReader(`{"n3_address":"192.0.2.10","n9_address":"192.0.2.20"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("update status %d: %s", w.Code, w.Body)
	}
	var got ebpf.IpEntrypointDataplaneConfig
	if err := bpf.GlobalConfig.Get(&got); err != nil {
		t.Fatal(err)
	}
	expected := initial
	expected.N3Ipv4Address = binary.LittleEndian.Uint32(net.ParseIP("192.0.2.10").To4())
	expected.N9Ipv4Address = binary.LittleEndian.Uint32(net.ParseIP("192.0.2.20").To4())
	if got != expected {
		t.Fatalf("address edit did not preserve the complete XDP configuration: got %+v want %+v", got, expected)
	}
}
