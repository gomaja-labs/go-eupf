//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestBufferEnvelopeAuthenticatesBeforeParsing(t *testing.T) {
	b := loadDatapath(t)
	if err := b.prepareBufferAdmission(); err != nil {
		t.Fatal(err)
	}
	if err := b.SetBufferGenericIngress(1, true); err != nil {
		t.Fatal(err)
	}
	frame := bufferedFrame(t, 2, 42)
	// Kernel test-run requires a real ingress device; loopback exists in both
	// the container and the minimum-kernel guest.
	envelope, err := b.BufferKernelEnvelope(frame, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func([]byte) []byte
		want   uint32
	}{
		{"valid", func(p []byte) []byte { return p }, 2},
		{"token", func(p []byte) []byte { p[22] ^= 1; return p }, 2},
		{"ingress", func(p []byte) []byte { binary.NativeEndian.PutUint32(p[18:], 2); return p }, 2},
		{"magic", func(p []byte) []byte { p[14] ^= 1; return p }, 2},
		{"short-cursor", func(p []byte) []byte { return p[:22] }, 2},
		{"short-frame", func(p []byte) []byte { return p[:43] }, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := (&UpfXdpActionStatistic{BpfObjects: b}).GetUpfExtStat()
			action, out := runDatapath(t, b, test.change(bytes.Clone(envelope)), &datapathContext{IngressIfindex: 1})
			if action != test.want || test.name == "valid" && !bytes.Equal(out, frame) {
				t.Fatalf("envelope action=%d want=%d or rendered frame changed", action, test.want)
			}
			if delta := before.Delta((&UpfXdpActionStatistic{BpfObjects: b}).GetUpfExtStat()); delta != (UpfCounters{}) {
				t.Fatalf("envelope counted as traffic: %+v", delta)
			}
		})
	}
	passed, dropped, err := b.BufferContinuationCounts()
	if err != nil || passed != 1 || dropped != 4 {
		t.Fatalf("continuation counts passed=%d dropped=%d error=%v", passed, dropped, err)
	}
	if err := b.SetBufferGenericIngress(1, false); err != nil {
		t.Fatal(err)
	}
	action, out := runDatapath(t, b, bytes.Clone(envelope), &datapathContext{IngressIfindex: 1})
	if action != 2 || !bytes.Equal(out, envelope) {
		t.Fatal("non-generic ingress consumed envelope")
	}
	passed, rejected, err := b.BufferContinuationCounts()
	if err != nil || passed != 1 || rejected != 5 {
		t.Fatalf("non-generic envelope counts: %d %d %v", passed, rejected, err)
	}
	if err := b.BufferToken.Put(uint32(0), uint64(1)); err == nil {
		t.Fatal("process token map is writable after initialization")
	}
}

// TestBufferAdmissionPreservesLocalExperimentalFrames sends an ordinary IEEE 802 Local
// Experimental EtherType 1 frame (not an envelope) through the initial and the
// BUFF-capable entrypoint. Both execute through kernel test-run with the same ingress context.
func TestBufferAdmissionPreservesLocalExperimentalFrames(t *testing.T) {
	b := loadDatapath(t)
	frame := ethernetDatapath(t, layers.EthernetType(0x88b5), bytes.Repeat([]byte{0x5a}, 46))
	before, _ := runDatapath(t, b, bytes.Clone(frame), &datapathContext{IngressIfindex: 1})
	if err := b.prepareBufferAdmission(); err != nil {
		t.Fatal(err)
	}
	after, _ := runDatapath(t, b, bytes.Clone(frame), &datapathContext{IngressIfindex: 1})
	passed, dropped, err := b.BufferContinuationCounts()
	t.Logf("LocalExperimental initial_action=%d buff_action=%d continuation_passed=%d continuation_dropped=%d err=%v", before, after, passed, dropped, err)
	if before != after || passed != 0 || dropped != 0 {
		t.Fatalf("88-B5 frame action: initial entrypoint action %d, BUFF entrypoint action %d", before, after)
	}
}
