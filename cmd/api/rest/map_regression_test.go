//go:build linux

package rest

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	dataplane "github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

// The subprocess keeps a bad kernel lookup destination from corrupting the test runner.
func TestPDRMapRoundTrip(t *testing.T) {
	if os.Getenv("EUPF_PDR_LOOKUP_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPDRMapRoundTrip$", "-test.v")
		cmd.Env = append(os.Environ(), "EUPF_PDR_LOOKUP_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("PDR lookup subprocess: %v\n%s", err, out)
		}
		return
	}
	gin.SetMode(gin.TestMode)
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4,
		ValueSize: uint32(unsafe.Sizeof(dataplane.IpEntrypointPdrInfo{})), MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	bpf := dataplane.NewBpfObjects()
	bpf.PdrMapTeidIp4 = m
	h := &ApiHandler{BpfObjects: bpf}
	r := gin.New()
	r.PUT("/pdr/:id", h.setUplinkPdrValue)
	r.GET("/pdr/:id", h.getUplinkPdrValue)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/pdr/7", strings.NewReader(`{"far_id":11,"qer_id":13,"outer_header_removal":2,"trace":true}`)))
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT status = %d: %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/pdr/7", nil))
	var got PdrUplinkElement
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.FarId != 11 || got.QerId != 13 || got.OuterHeaderRemoval != 2 || !got.Trace {
		t.Fatalf("PDR read did not preserve the stored fields: %+v", got)
	}
}

func TestDownlinkIPv4PDRUsesIPv4Map(t *testing.T) {
	gin.SetMode(gin.TestMode)
	bpf := dataplane.NewBpfObjects()
	for _, size := range []uint32{4, 16} {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: size,
			ValueSize: uint32(unsafe.Sizeof(dataplane.IpEntrypointPdrInfo{})), MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = m.Close() }()
		if size == 4 {
			bpf.PdrMapDownlinkIp4 = m
		} else {
			bpf.PdrMapDownlinkIp6 = m
		}
	}
	h := &ApiHandler{BpfObjects: bpf}
	r := gin.New()
	r.PUT("/pdr/:id", h.setDownlinkPdrValue)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/pdr/192.0.2.1", strings.NewReader(`{"far_id":11}`)))
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT status = %d: %s", w.Code, w.Body)
	}
	var got dataplane.IpEntrypointPdrInfo
	if err := bpf.PdrMapDownlinkIp4.Lookup(net.ParseIP("192.0.2.1").To4(), &got); err != nil {
		t.Fatalf("IPv4 PDR missing from IPv4 map: %v", err)
	}
	if got.DefaultPdr.FarId != 11 {
		t.Errorf("FAR = %d, want 11", got.DefaultPdr.FarId)
	}
}
