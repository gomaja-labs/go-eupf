//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	cilium "github.com/cilium/ebpf"
)

func TestBufferingKeepsOrdinaryFARLayout(t *testing.T) {
	if size := unsafe.Sizeof(IpEntrypointFarInfo{}); size != 16 {
		t.Fatalf("kernel FAR grew beyond base: %d bytes", size)
	}
}

func TestBufferReleaseVersionStaysOutsideFORW(t *testing.T) {
	b := loadDatapath(t)
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	far := FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, BufferSessionID: 42, BufferCookie: 7}
	if err := b.UpdateFar(3, far); err != nil {
		t.Fatal(err)
	}
	var value IpEntrypointFarInfo
	if err := b.FarMap.Lookup(uint32(3), &value); err != nil {
		t.Fatal(err)
	}
	if value.Action&2 != 0 || value.Action&0x84 != 0x84 {
		t.Fatalf("release version reached FORW: action=%x", value.Action)
	}
}

func TestBufferReleaseForwardsImmediatelyAfterLastHandover(t *testing.T) {
	b := loadDatapath(t)
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	far := FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2})}
	if err := b.UpdateFar(3, far); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}); err != nil {
		t.Fatal(err)
	}
	packet := bufferedFrame(t, 2, 100)
	action, expected := runDatapath(t, b, packet)
	if action != 4 {
		t.Fatalf("plain FORW did not redirect: %d", action)
	}
	far.BufferSessionID, far.BufferCookie = 42, 7
	if err := b.UpdateFar(3, far); err != nil {
		t.Fatal(err)
	}
	state, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 1, Mode: BufferDrain, Ready: 1})
	if err != nil || state.Mode != BufferForward {
		t.Fatalf("empty release did not open: %+v %v", state, err)
	}
	action, got := runDatapath(t, b, packet)
	if action != 4 || !bytes.Equal(got, expected) {
		for i := range min(len(got), len(expected)) {
			if got[i] != expected[i] {
				t.Logf("byte %d: got=%d expected=%d", i, got[i], expected[i])
			}
		}
		t.Fatalf("release after hand-over: action=%d equal=%t", action, bytes.Equal(got, expected))
	}
	outstanding, dropped, err := b.BufferPoolUsage()
	if err != nil || outstanding != 0 || dropped != 0 {
		t.Fatalf("empty release acquired storage: %d %d %v", outstanding, dropped, err)
	}
}

func TestBufferBindingReclaimedWithItsFARVersion(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "commit"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			b := loadDatapath(t)
			for range 3 {
				if _, err := b.GetNextFAR(); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := b.BeginRuleTransaction(42)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := tx.Rollback(); err != nil {
					t.Error(err)
				}
			}()
			slot, err := tx.NewFar(FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7})
			if err != nil {
				t.Fatal(err)
			}
			var binding bufferBinding
			if err := b.BufferBindings.Lookup(slot, &binding); err != nil || binding.SessionID != 42 || binding.Cookie != 7 {
				t.Fatalf("unpublished binding=%+v %v", binding, err)
			}
			if rollback {
				if err := tx.Rollback(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
				retired, err := b.BeginRuleTransaction(42)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := retired.Rollback(); err != nil {
						t.Error(err)
					}
				}()
				if err := retired.DeleteFar(slot); err != nil {
					t.Fatal(err)
				}
				if err := retired.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			if err := b.SynchronizeRules(); err != nil {
				t.Fatal(err)
			}
			if err := b.BufferBindings.Lookup(slot, &binding); !isKeyAbsent(err) {
				t.Fatalf("retired binding still exists: %+v %v", binding, err)
			}
		})
	}
}

func TestBufferContinuationsShareLiveConfiguration(t *testing.T) {
	b := loadDatapath(t)
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	far := FarInfo{Action: 4, OuterHeaderCreation: 1, Teid: 200, RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), BufferSessionID: 42, BufferCookie: 7}
	if err := b.UpdateFar(3, far); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}); err != nil {
		t.Fatal(err)
	}
	packet := bufferedFrame(t, 2, 100)
	if action, _ := runDatapath(t, b, packet); action != 1 {
		t.Fatalf("admission action=%d", action)
	}
	reader.SetDeadline(time.Now().Add(time.Second))
	record, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	far.Action = 2
	if err := b.UpdateFar(3, far); err != nil {
		t.Fatal(err)
	}
	if _, err := b.BufferKernelIngressProgram(); err != nil {
		t.Fatal(err)
	}
	var cfg IpEntrypointDataplaneConfig
	if err := b.GlobalConfig.Get(&cfg); err != nil {
		t.Fatal(err)
	}
	cfg.N3Ipv4Address = binary.LittleEndian.Uint32(net.IP{192, 0, 2, 10})
	if err := b.GlobalConfig.Set(cfg); err != nil {
		t.Fatal(err)
	}
	for name, collection := range map[string]*cilium.Collection{"admission": b.admissionCollection, "renderer": b.renderCollection} {
		var current IpEntrypointDataplaneConfig
		if err := collection.Variables["global_config"].Get(&current); err != nil || current != cfg {
			t.Fatalf("%s uses stale configuration: %+v %v", name, current, err)
		}
	}
	rendered, err := b.RenderBufferedPacket(record, 3)
	if err != nil || rendered.Action != 4 || !bytes.Equal(rendered.Frame[26:30], net.IP{192, 0, 2, 10}) {
		t.Fatalf("render source did not change: action=%d error=%v", rendered.Action, err)
	}
	if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 1, Mode: BufferDrain, Ready: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Sequence: record.Sequence, Downlink: true}); err != nil {
		t.Fatal(err)
	}
	action, current := runDatapath(t, b, packet)
	if action != 4 || !bytes.Equal(current[26:30], net.IP{192, 0, 2, 10}) {
		t.Fatalf("native release source did not change: action=%d", action)
	}
}

func TestBufferMetadataControlDoesNotLoadOutput(t *testing.T) {
	b := loadDatapath(t)
	if b.UpfBufferControlFunc != nil || b.UpfBufferAdmissionFunc != nil {
		t.Fatal("ordinary load prepared unused buffering programs")
	}
	if err := b.UpfIpEntrypointFunc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	state, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
	if err != nil || state.Mode != BufferHold {
		t.Fatalf("metadata control required packet output: %+v %v", state, err)
	}
	if b.UpfBufferControlFunc == nil || b.UpfBufferAdmissionFunc != nil || b.admissionCollection != nil || b.renderCollection != nil {
		t.Fatal("metadata preparation loaded output")
	}
}
