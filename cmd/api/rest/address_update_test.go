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
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

func TestAddressUpdateReachesDataplaneConfig(t *testing.T) {
	t.Chdir(t.TempDir())
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
		N3Ipv4Address: binary.LittleEndian.Uint32(net.ParseIP("192.0.2.1").To4()),
		N9Ipv4Address: binary.LittleEndian.Uint32(net.ParseIP("192.0.2.2").To4()),
	}
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
	if got.N3Ipv4Address == initial.N3Ipv4Address || got.N9Ipv4Address == initial.N9Ipv4Address {
		t.Errorf("successful address update left kernel addresses unchanged: N3=%d N9=%d", got.N3Ipv4Address, got.N9Ipv4Address)
	}
}
