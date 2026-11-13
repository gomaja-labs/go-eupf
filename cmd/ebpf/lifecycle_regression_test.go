//go:build linux

package ebpf

import (
	"encoding/binary"
	"os"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"

	cilium "github.com/cilium/ebpf"
)

func TestMapLayouts(t *testing.T) {
	spec, err := LoadIpEntrypoint()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"pdr_map_teid_ip4": IpEntrypointPdrIndex{},
		"pdr_buckets":      IpEntrypointPdrBucket{},
		"far_map":          IpEntrypointFarInfo{},
		"qer_map":          IpEntrypointQerInfo{},
		"urr_map":          IpEntrypointUrrInfo{},
	} {
		typ := reflect.TypeOf(value)
		if uintptr(spec.Maps[name].ValueSize) != typ.Size() {
			t.Errorf("%s Go=%d C=%d", name, typ.Size(), spec.Maps[name].ValueSize)
		}
		checkMapMemberLayout(t, name, typ, spec.Maps[name].Value)
	}

}

func checkMapMemberLayout(t *testing.T, path string, goType reflect.Type, cType btf.Type) {
	t.Helper()
	switch c := btf.UnderlyingType(cType).(type) {
	case *btf.Array:
		if goType.Kind() != reflect.Array || uint32(goType.Len()) != c.Nelems {
			t.Errorf("%s array shape differs", path)
			return
		}
		checkMapMemberLayout(t, path+"[]", goType.Elem(), c.Type)
	case *btf.Struct:
		if goType.Kind() != reflect.Struct || goType.Size() != uintptr(c.Size) {
			t.Errorf("%s struct shape differs", path)
			return
		}
		for _, member := range c.Members {
			found := false
			for field := range goType.Fields() {
				if strings.EqualFold(field.Name, strings.ReplaceAll(member.Name, "_", "")) {
					found = true
					if field.Offset*8 != uintptr(member.Offset) {
						t.Errorf("%s.%s Go offset=%d C offset=%d bits", path, field.Name, field.Offset*8, member.Offset)
					}
					checkMapMemberLayout(t, path+"."+field.Name, field.Type, member.Type)
					break
				}
			}
			if !found {
				t.Errorf("%s C member %s missing from Go", path, member.Name)
			}
		}
	}
}

func TestLoaderClosesMapDescriptors(t *testing.T) {
	beforeGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(beforeGC)
	count := func() int {
		fs, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(fs)
	}
	// Warm up runtime and the library before measuring ownership.
	b := NewBpfObjects()
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	before := count()
	for range 3 {
		b := NewBpfObjects()
		if err := b.Load(); err != nil {
			t.Fatal(err)
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if after := count(); after != before {
		t.Errorf("Load+Close retained %d descriptors", after-before)
	}
}

func TestNotifyCloseStopsLoop(t *testing.T) {
	b := loadDatapath(t)
	l, err := NewSdfNotifyListener(b.SdfNotifyMap)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { l.ReadEventLoop(); close(done) }()
	deadline := time.Now().Add(time.Second)
	for {
		l.mu.Lock()
		running := l.running
		l.mu.Unlock()
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read loop did not start")
		}
		time.Sleep(time.Millisecond)
	}
	l.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("read loop did not stop after Close")
	}
	// Close owns cancellation, and can be repeated even after loop exit.
	l.Close()
}

func TestQerMapRoundTripAndDelete(t *testing.T) {
	b := loadDatapath(t)
	want := QerInfo{GateStatusUL: 1, GateStatusDL: 1, Qfi: 17, Dscp: 32, MaxBitrateUL: 4000000000, MaxBitrateDL: 3000000000}
	id, err := b.NewQer(want)
	if err != nil {
		t.Fatal(err)
	}
	values, err := ListQerMapContents(b.QerMap)
	if err != nil {
		t.Fatal(err)
	}
	if values[id].MaxBitrateUL != want.MaxBitrateUL || values[id].GateStatusDL != 1 {
		t.Fatalf("QER did not round trip: %+v", values[id])
	}
	if err := b.DeleteQer(id); err != nil {
		t.Fatal(err)
	}
	var zero IpEntrypointQerInfo
	if err := b.QerMap.Lookup(id, &zero); err != nil {
		t.Fatal(err)
	}
	if zero != (IpEntrypointQerInfo{}) {
		t.Errorf("delete left QER state: %+v", zero)
	}
	if err := b.DeleteQer(0); err == nil {
		t.Error("deleted reserved QER 0")
	}
}

func TestPublicationCreatesAbsentKey(t *testing.T) {
	b := loadDatapath(t)
	if err := b.PutPdrUplink(100, PdrInfo{PdrID: 1, FarId: 1}); err != nil {
		t.Fatal(err)
	}
	var got IpEntrypointPdrInfo
	if err := b.LookupUplinkPDR(100, &got); err != nil || got.Count != 1 {
		t.Fatalf("absent key not initialized: %+v %v", got, err)
	}
}

func TestIPv6SdfNotification(t *testing.T) {
	b := loadDatapath(t)
	l, err := NewSdfNotifyListener(b.SdfNotifyMap)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go l.ReadEventLoop()
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{SessionID: (1 << 40) + 9, PdrID: 7, FarId: 1, QerIDs: []uint32{1}, NotifyFlag: true, SdfFilter: []SdfFilter{anyDatapathFilter(17)}}); err != nil {
		t.Fatal(err)
	}
	runDatapath(t, b, gtpDatapath(t, udpDatapath(t, true), nil, 0x30, false))
	select {
	case event := <-l.GetNotificationChannel():
		if event.SessionID != (1<<40)+9 || event.PDRID != 7 || !strings.Contains(event.SDFFilter, "2001:db8::1/128 1234") {
			t.Errorf("wrong event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("no IPv6 notification")
	}
}

func TestMalformedSdfRecord(t *testing.T) {
	for _, cookie := range []uint16{0x1ea1, 0x2ea2} {
		minimum := 27
		if cookie == 0x2ea2 {
			minimum = 51
		}
		for n := 0; n < minimum; n++ {
			raw := make([]byte, n)
			if n >= 2 {
				binary.LittleEndian.PutUint16(raw, cookie)
			}
			if _, err := parseSdfRecord(&perf.Record{RawSample: raw}); err == nil {
				t.Errorf("cookie=%x length=%d accepted", cookie, n)
			}
		}
	}
}

func TestUrrUpdatePreservesLiveCounters(t *testing.T) {
	b := loadDatapath(t)
	runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false))
	before, err := b.GetUrr(1)
	if err != nil {
		t.Fatal(err)
	}
	if before.UplinkVolume == 0 {
		t.Fatal("no traffic counted")
	}
	if err := b.UpdateUrr(1, UrrInfo{VolumeThreshold: 1000}); err != nil {
		t.Fatal(err)
	}
	after, err := b.GetUrr(1)
	if err != nil {
		t.Fatal(err)
	}
	if after.UplinkVolume != before.UplinkVolume {
		t.Errorf("URR update replaced live counters: before=%d after=%d", before.UplinkVolume, after.UplinkVolume)
	}
}

func TestLowRateAdmitsOnePacket(t *testing.T) {
	b := loadDatapath(t)
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{UlMaximumBitrate: 1})
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	action, _ := runDatapath(t, b, packet)
	if action == 1 {
		t.Error("nonzero low MBR never admits a packet larger than its 5ms budget")
	}
	action, _ = runDatapath(t, b, packet)
	if action != 1 {
		t.Error("low MBR admitted a second packet before its transmission interval")
	}
}

func TestFailedRuleCreationReturnsID(t *testing.T) {
	for _, kind := range []string{"FAR", "QER", "URR"} {
		t.Run(kind, func(t *testing.T) {
			sizes := map[string]uintptr{"FAR": unsafe.Sizeof(IpEntrypointFarInfo{}), "QER": unsafe.Sizeof(IpEntrypointQerInfo{}), "URR": unsafe.Sizeof(IpEntrypointUrrInfo{})}
			m, err := cilium.NewMap(&cilium.MapSpec{Type: cilium.Array, KeySize: 4, ValueSize: uint32(sizes[kind]), MaxEntries: 8})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			b := NewBpfObjects()
			b.FarMap, b.QerMap, b.UrrMap = m, m, m
			b.farIdTracker, b.qerIdTracker, b.urrIdTracker = NewIdTracker(8), NewIdTracker(8), NewIdTracker(8)
			var next uint32
			switch kind {
			case "FAR":
				_, err = b.NewFar(FarInfo{})
				next, _ = b.GetNextFAR()
			case "QER":
				_, err = b.NewQer(QerInfo{})
				next, _ = b.GetNextQER()
			case "URR":
				_, err = b.NewUrr(UrrInfo{})
				next, _ = b.GetNextURR()
			}
			if err == nil {
				t.Fatal("closed map accepted a new rule")
			}
			if next != 1 {
				t.Errorf("failed %s creation leaked ID 1; next=%d", kind, next)
			}
		})
	}
}

func TestAllProgramsLoad(t *testing.T) {
	for _, entry := range []struct {
		name string
		load func() (*cilium.CollectionSpec, error)
	}{
		{"zero", LoadZeroEntrypoint}, {"n3", LoadN3Entrypoint}, {"n6", LoadN6Entrypoint},
	} {
		t.Run(entry.name, func(t *testing.T) {
			if err := os.MkdirAll("/sys/fs/bpf/upf_pipeline", 0750); err != nil {
				t.Fatal(err)
			}
			spec, err := entry.load()
			if err != nil {
				t.Fatal(err)
			}
			collection, err := cilium.NewCollectionWithOptions(spec, cilium.CollectionOptions{Maps: cilium.MapOptions{PinPath: "/sys/fs/bpf/upf_pipeline"}})
			if err != nil {
				t.Fatalf("%+v", err)
			}
			collection.Close()
		})
	}
	loadDatapath(t)
}
