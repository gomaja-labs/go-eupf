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
	bpf := dataplane.NewBpfObjects()
	bpf.SetPdrMapSize(4)
	if err := bpf.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bpf.Close(); err != nil {
			t.Error(err)
		}
	})
	h := &ApiHandler{BpfObjects: bpf}
	r := gin.New()
	if err := bpf.PutPdrUplink(7, dataplane.PdrInfo{FarId: 11, QerIDs: []uint32{13}, OuterHeaderRemoval: 2, TraceFlag: true}); err != nil {
		t.Fatal(err)
	}
	r.GET("/pdr/:id", h.getUplinkPdrValue)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/pdr/7", nil))
	var got PdrMapElement
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].FarId != 11 || len(got.Rules[0].QerIDs) != 1 || got.Rules[0].QerIDs[0] != 13 || got.Rules[0].OuterHeaderRemoval != 2 || !got.Rules[0].TraceFlag {
		t.Fatalf("PDR read did not preserve the stored fields: %+v", got)
	}
}

func TestDownlinkIPv4PDRUsesIPv4Map(t *testing.T) {
	gin.SetMode(gin.TestMode)
	bpf := dataplane.NewBpfObjects()
	bpf.SetPdrMapSize(4)
	if err := bpf.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bpf.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := bpf.PutPdrDownlink(net.ParseIP("192.0.2.1"), dataplane.PdrInfo{FarId: 11}); err != nil {
		t.Fatal(err)
	}
	got, err := bpf.LookupDownlinkPDR(net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatalf("IPv4 PDR missing from IPv4 map: %v", err)
	}
	if got.Entries[0].Pdr.FarId != 11 {
		t.Errorf("FAR = %d, want 11", got.Entries[0].Pdr.FarId)
	}
}

func TestMapWritesCannotBypassSessionTransactions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	b := dataplane.NewBpfObjects()
	makeMap := func(typ ebpf.MapType, size uintptr) *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: typ, KeySize: 4, ValueSize: uint32(size), MaxEntries: 4})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	b.PdrMapTeidIp4 = makeMap(ebpf.Hash, unsafe.Sizeof(dataplane.IpEntrypointPdrIndex{}))
	b.PdrMapDownlinkIp4 = makeMap(ebpf.Hash, unsafe.Sizeof(dataplane.IpEntrypointPdrIndex{}))
	b.FarMap = makeMap(ebpf.Array, unsafe.Sizeof(dataplane.IpEntrypointFarInfo{}))
	b.QerMap = makeMap(ebpf.Array, unsafe.Sizeof(dataplane.IpEntrypointQerInfo{}))
	h := &ApiHandler{BpfObjects: b}
	r := gin.New()
	r.PUT("/up/:id", h.setUplinkPdrValue)
	r.PUT("/down/:id", h.setDownlinkPdrValue)
	r.PUT("/far/:id", h.setFarValue)
	r.PUT("/qer/:id", h.setQerValue)
	for _, path := range []string{"/up/1", "/down/192.0.2.1", "/far/1", "/qer/1"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"far_id":1}`)))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status=%d permits unmanaged rule writes", path, w.Code)
		}
	}
}
