//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
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

func TestPublishedFARFieldsRemainConsistent(t *testing.T) {
	b := loadDatapath(t)
	for range 3 {
		if _, err := b.GetNextFAR(); err != nil {
			t.Fatal(err)
		}
	}
	forward := FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2})}
	current, err := b.NewFar(forward)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 9, PdrID: 1, FarId: current, QerIDs: []uint32{1}, UrrIDs: []uint32{1}}); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	updates := 0
	capacityRetries := 0
	go func() {
		defer wg.Done()
		defer pinPublicationCPU(t, 2)()
		for !stop.Load() {
			tx, err := b.BeginRuleTransaction(9)
			if err != nil {
				t.Error(err)
				return
			}
			info := forward
			if updates&1 == 0 {
				info = FarInfo{Action: 1}
			}
			next, err := tx.NewFar(info)
			if err == nil {
				err = tx.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 9, PdrID: 1, FarId: next, QerIDs: []uint32{1}, UrrIDs: []uint32{1}})
			}
			if err == nil {
				err = tx.DeleteFar(current)
			}
			if err == nil {
				err = tx.Commit()
			}
			if err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					t.Error(errors.Join(err, rollbackErr))
					return
				}
				if errors.Is(err, ErrRuleCapacity) {
					capacityRetries++
					continue
				}
				t.Error(err)
				return
			}
			current = next
			updates++
		}
	}()
	defer func() { stop.Store(true); wg.Wait() }()
	defer pinPublicationCPU(t, 5)()
	packet := ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false))
	deadline := time.Now().Add(publicationChurnDuration(t))
	packets, mixed, forwarded := 0, 0, 0
	for time.Now().Before(deadline) {
		_, out, err := b.UpfIpEntrypointFunc.Test(packet)
		if err != nil {
			t.Fatal(err)
		}
		packets++
		decoded := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
		if g, ok := decoded.Layer(layers.LayerTypeGTPv1U).(*layers.GTPv1U); ok {
			forwarded++
			ip4, _ := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if g.TEID != 200 || !ip4.DstIP.Equal(net.IP{198, 18, 1, 2}) {
				mixed++
			}
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("updates=%d packets=%d forwarded=%d capacity-retries=%d mixed-FAR=%d", updates, packets, forwarded, capacityRetries, mixed)
	if mixed != 0 || updates < 2 || forwarded == 0 {
		t.Fatal("incoherent FAR output or inactive churn")
	}
}

func qerReaderProbe(t *testing.T, b *BpfObjects) (*cilium.Program, *cilium.Map) {
	t.Helper()
	result, err := cilium.NewMap(&cilium.MapSpec{Type: cilium.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = result.Close() })
	offset := int16(unsafe.Offsetof(IpEntrypointPdrBucket{}.Info) + unsafe.Offsetof(IpEntrypointPdrInfo{}.Entries) + unsafe.Offsetof(IpEntrypointPdrEntry{}.Pdr) + 4)
	ins := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 100, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.LoadMapPtr(asm.R1, b.PdrMapTeidIp4.FD()), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R1, asm.R0, int16(unsafe.Offsetof(IpEntrypointPdrIndex{}.Slot)), asm.Word), asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.LoadMapPtr(asm.R1, b.PdrBuckets.FD()), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R1, asm.R0, offset, asm.Word), asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.LoadMapPtr(asm.R1, b.QerMap.FD()), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"),
		asm.Mov.Reg(asm.R6, asm.R0), asm.LoadMem(asm.R7, asm.R6, int16(unsafe.Offsetof(IpEntrypointQerInfo{}.UlGateStatus)), asm.Byte), asm.Mov.Imm(asm.R8, 0),
		asm.LoadMem(asm.R9, asm.R6, 0, asm.DWord).WithSymbol("loop"), asm.Add.Imm(asm.R8, 1), asm.JLT.Imm(asm.R8, 20000, "loop"),
		asm.LoadMem(asm.R9, asm.R6, int16(unsafe.Offsetof(IpEntrypointQerInfo{}.UlMaximumBitrate)), asm.DWord), asm.JEq.Reg(asm.R9, asm.R7, "out"),
		asm.StoreImm(asm.RFP, -8, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.LoadMapPtr(asm.R1, result.FD()), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"), asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord), asm.Mov.Imm(asm.R0, 2).WithSymbol("out"), asm.Return(),
	}
	probe, err := cilium.NewProgram(&cilium.ProgramSpec{Type: cilium.XDP, Instructions: ins, License: "GPL"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	return probe, result
}
func TestPublishedQERGateAndRateRemainConsistent(t *testing.T) {
	b := loadDatapath(t)
	if _, err := b.GetNextQER(); err != nil {
		t.Fatal(err)
	}
	anchor, err := b.NewQer(QerInfo{})
	if err != nil {
		t.Fatal(err)
	}
	current := anchor
	if err := b.PutPdrUplink(100, PdrInfo{SessionID: 10, PdrID: 1, FarId: 1, QerIDs: []uint32{current}}); err != nil {
		t.Fatal(err)
	}
	probe, result := qerReaderProbe(t, b)
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	updates := 0
	capacityRetries := 0
	go func() {
		defer wg.Done()
		defer pinPublicationCPU(t, 2)()
		for !stop.Load() {
			tx, err := b.BeginRuleTransaction(10)
			if err != nil {
				t.Error(err)
				return
			}
			value := uint64((updates / 2) & 1)
			next, err := tx.NewQer(QerInfo{PolicerID: anchor, GateStatusUL: uint8(value), MaxBitrateUL: value})
			if err == nil {
				err = tx.PutPdrUplink(100, PdrInfo{SessionID: 10, PdrID: 1, FarId: 1, QerIDs: []uint32{next}})
			}
			if err == nil {
				err = tx.RetireQer(current)
			}
			if err == nil {
				err = tx.Commit()
			}
			if err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					t.Error(errors.Join(err, rollbackErr))
					return
				}
				if errors.Is(err, ErrRuleCapacity) {
					capacityRetries++
					continue
				}
				t.Error(err)
				return
			}
			current = next
			updates++
		}
	}()
	defer func() { stop.Store(true); wg.Wait() }()
	defer pinPublicationCPU(t, 5)()
	for range 50 {
		if _, err := probe.Run(&cilium.RunOptions{Data: make([]byte, 64), Repeat: 100}); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	var mixed uint64
	if err := result.Lookup(uint32(0), &mixed); err != nil {
		t.Fatal(err)
	}
	t.Logf("updates=%d capacity-retries=%d mixed-QER=%d", updates, capacityRetries, mixed)
	if mixed != 0 || updates < 2 {
		t.Fatal("mixed QER fields or inactive churn")
	}
}

func TestReplacementQERMetersAgainstSharedState(t *testing.T) {
	b := loadDatapath(t)
	if _, err := b.GetNextQER(); err != nil {
		t.Fatal(err)
	}
	anchor, err := b.NewQer(QerInfo{MaxBitrateUL: 1000000})
	if err != nil {
		t.Fatal(err)
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	var original IpEntrypointQerInfo
	if err := b.QerMap.Lookup(anchor, &original); err != nil {
		t.Fatal(err)
	}
	original.UlStart = uint64(now.Nano()) + uint64(time.Minute)
	if err := b.QerMap.Put(anchor, &original); err != nil {
		t.Fatal(err)
	}
	version, err := b.NewQer(QerInfo{PolicerID: anchor, MaxBitrateUL: 1000000})
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]uint32{{version}, {1, version}} {
		if err := b.PutPdrUplink(10, PdrInfo{PdrID: 1, FarId: 1, OuterHeaderRemovalPresent: true, QerIDs: ids}); err != nil {
			t.Fatal(err)
		}
		action, _ := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false))
		if action != 1 {
			t.Fatalf("replacement reset the policer budget with %d bindings: %d", len(ids), action)
		}
	}

}
