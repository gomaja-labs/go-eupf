//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBufferEnvelopeAuthenticatesBeforeParsing(t *testing.T) {
	b := loadDatapath(t)
	if err := b.prepareBufferAdmission(); err != nil {
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
		{"token", func(p []byte) []byte { p[22] ^= 1; return p }, 1},
		{"ingress", func(p []byte) []byte { binary.NativeEndian.PutUint32(p[18:], 2); return p }, 1},
		{"magic", func(p []byte) []byte { p[14] ^= 1; return p }, 1},
		{"short-cursor", func(p []byte) []byte { return p[:22] }, 1},
		{"short-frame", func(p []byte) []byte { return p[:43] }, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := (&UpfXdpActionStatistic{BpfObjects: b}).GetUpfExtStat()
			action, out := runDatapath(t, b, test.change(bytes.Clone(envelope)), &datapathContext{IngressIfindex: 1})
			if action != test.want || action == 2 && !bytes.Equal(out, frame) {
				t.Fatalf("envelope action=%d want=%d or rendered frame changed", action, test.want)
			}
			if delta := before.Delta((&UpfXdpActionStatistic{BpfObjects: b}).GetUpfExtStat()); delta != (UpfCounters{}) {
				t.Fatalf("envelope counted as traffic: %+v", delta)
			}
		})
	}
	passed, dropped, err := b.BufferContinuationCounts()
	if err != nil || passed != 1 || dropped != 5 {
		t.Fatalf("continuation counts passed=%d dropped=%d error=%v", passed, dropped, err)
	}
	if err := b.BufferToken.Put(uint32(0), uint64(1)); err == nil {
		t.Fatal("process token map is writable after initialization")
	}
}
