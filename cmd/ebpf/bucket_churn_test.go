//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"
)

func pinPublicationCPU(t *testing.T, cpu int) func() {
	t.Helper()
	runtime.LockOSThread()
	var original, next unix.CPUSet
	if err := unix.SchedGetaffinity(0, &original); err != nil {
		t.Fatal(err)
	}
	next.Set(cpu % runtime.NumCPU())
	if err := unix.SchedSetaffinity(0, &next); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := unix.SchedSetaffinity(0, &original); err != nil {
			t.Error(err)
		}
		runtime.UnlockOSThread()
	}
}

// Hold the stable array pointer across a long XDP invocation while the normal
// transaction path replaces buckets. This is the old hash-element lifetime
// reproducer, with the same spin and CPU pairing, following the shipped ABI.
func bucketReaderProbe(t *testing.T, b *BpfObjects) (*cilium.Program, *cilium.Map) {
	t.Helper()
	result, err := cilium.NewMap(&cilium.MapSpec{Type: cilium.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = result.Close() })
	ins := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 100, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.LoadMapPtr(asm.R1, b.PdrMapTeidIp4.FD()), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R1, asm.R0, int16(unsafe.Offsetof(IpEntrypointPdrIndex{}.Slot)), asm.Word), asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.LoadMapPtr(asm.R1, b.PdrBuckets.FD()), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word), asm.JNE.Imm(asm.R1, 100, "out"), asm.Mov.Reg(asm.R6, asm.R0), asm.Mov.Imm(asm.R8, 0),
		asm.LoadMem(asm.R9, asm.R6, int16(unsafe.Offsetof(IpEntrypointPdrBucket{}.Info)), asm.DWord).WithSymbol("loop"), asm.Add.Imm(asm.R8, 1), asm.JLT.Imm(asm.R8, 20000, "loop"),
		asm.LoadMem(asm.R9, asm.R6, int16(unsafe.Offsetof(IpEntrypointPdrBucket{}.Info)), asm.DWord), asm.JEq.Imm(asm.R9, 0xA, "out"),
		asm.StoreImm(asm.RFP, -8, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.LoadMapPtr(asm.R1, result.FD()), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"), asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord), asm.Mov.Imm(asm.R0, 2).WithSymbol("out"), asm.Return(),
	}
	probe, err := cilium.NewProgram(&cilium.ProgramSpec{Type: cilium.XDP, Instructions: ins, License: "GPL"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	return probe, result
}
func TestPublishedBucketsKeepReaderMemory(t *testing.T) {
	b := loadDatapath(t)
	put := func(owner uint64, key, precedence uint32) error {
		return b.PutPdrUplink(key, PdrInfo{SessionID: owner, PdrID: 1, Precedence: precedence, FarId: 1})
	}
	if err := put(0xA, 100, 0); err != nil {
		t.Fatal(err)
	}
	if err := put(0xB, 200, 0); err != nil {
		t.Fatal(err)
	}
	probe, result := bucketReaderProbe(t, b)
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	updates := 0
	go func() {
		defer wg.Done()
		defer pinPublicationCPU(t, 2)()
		for !stop.Load() {
			for _, key := range []uint32{100, 200} {
				if err := put(uint64(key/100+9), key, uint32(updates)); err != nil {
					t.Error(err)
					return
				}
				updates++
			}
		}
	}()
	defer func() { stop.Store(true); wg.Wait() }()
	defer pinPublicationCPU(t, 5)()
	for range 200 {
		if _, err := probe.Run(&cilium.RunOptions{Data: make([]byte, 64), Repeat: 100}); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	var mismatch uint64
	if err := result.Lookup(uint32(0), &mismatch); err != nil {
		t.Fatal(err)
	}
	t.Logf("transactions=%d cross-key-reads=%d", updates, mismatch)
	if mismatch != 0 {
		t.Fatalf("stable bucket memory reused under %d readers", mismatch)
	}
}

func TestPublishedBucketsDoNotCrossSessions(t *testing.T) {
	b := loadDatapath(t)
	for _, row := range []struct {
		key      uint32
		owner    uint64
		far, urr uint32
	}{{100, 10, 1, 1}, {200, 11, 3, 2}} {
		p := PdrInfo{SessionID: row.owner, PdrID: 1, OuterHeaderRemovalPresent: true, FarId: row.far, UrrIDs: []uint32{row.urr}, SdfFilter: []SdfFilter{anyDatapathFilter(17)}}
		if err := b.PutPdrUplink(row.key, p); err != nil {
			t.Fatal(err)
		}
	}
	var a, other IpEntrypointPdrIndex
	if err := b.PdrMapTeidIp4.Lookup(uint32(100), &a); err != nil {
		t.Fatal(err)
	}
	if err := b.PdrMapTeidIp4.Lookup(uint32(200), &other); err != nil {
		t.Fatal(err)
	}
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	binary.BigEndian.PutUint32(packet[46:50], 100)
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	updates := 0
	go func() {
		defer wg.Done()
		defer pinPublicationCPU(t, 2)()
		for !stop.Load() {
			// Deliberately force replacement rather than the production in-place update,
			// exercising key checks even under kernel element recycling.
			if err := b.PdrMapTeidIp4.Put(uint32(100), &a); err != nil {
				t.Error(err)
				return
			}
			if err := b.PdrMapTeidIp4.Put(uint32(200), &other); err != nil {
				t.Error(err)
				return
			}
			updates += 2
		}
	}()
	defer func() { stop.Store(true); wg.Wait() }()
	defer pinPublicationCPU(t, 5)()
	deadline := time.Now().Add(2 * time.Second)
	packets, bad, errorIndications := 0, 0, 0
	for time.Now().Before(deadline) {
		action, out, err := b.UpfIpEntrypointFunc.Test(packet)
		if err != nil {
			t.Fatal(err)
		}
		packets++
		p := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
		if g, ok := p.Layer(layers.LayerTypeGTPv1U).(*layers.GTPv1U); ok && action != 1 && action != 2 {
			if g.MessageType == 26 {
				errorIndications++
			} else if g.TEID != 100 {
				bad++
			}
		}
	}
	stop.Store(true)
	wg.Wait()
	var usage IpEntrypointUrrInfo
	if err := b.UrrMap.Lookup(uint32(2), &usage); err != nil {
		t.Fatal(err)
	}
	t.Logf("puts=%d packets=%d cross-key-output=%d false-error-indications=%d other-session-usage=%+v", updates, packets, bad, errorIndications, usage)
	if bad != 0 || errorIndications != 0 || usage.Ul != 0 || usage.Dl != 0 {
		t.Fatal("packet crossed session context")
	}
}

func TestPublishedBucketKeyTagRejectsRecycledIndex(t *testing.T) {
	b := loadDatapath(t)
	if err := b.PutPdrUplink(100, PdrInfo{SessionID: 10, PdrID: 1, FarId: 1}); err != nil {
		t.Fatal(err)
	}
	var other IpEntrypointPdrIndex
	if err := b.PdrMapTeidIp4.Lookup(uint32(100), &other); err != nil {
		t.Fatal(err)
	}
	if err := b.PdrMapTeidIp4.Put(uint32(10), &other); err != nil {
		t.Fatal(err)
	}
	action, _ := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false))
	if action != 1 {
		t.Fatalf("wrong-key index forwarded or generated Error Indication: %d", action)
	}
	// Same numeric key in the other hash map must also fail the kind tag.
	ip := net.IP{100, 0, 0, 0}
	if err := b.PdrMapDownlinkIp4.Put(ip.To4(), &other); err != nil {
		t.Fatal(err)
	}
	packet := ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false))
	copy(packet[30:34], ip)
	action, _ = runDatapath(t, b, packet)
	if action != 2 {
		t.Fatalf("wrong-kind index was matched: %d", action)
	}
}
