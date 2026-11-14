//go:build linux

package ebpf

import (
	"encoding/binary"
	"testing"
)

func TestBufferMapSizingMatchesTheMemoryPlan(t *testing.T) {
	spec, err := LoadIpEntrypoint()
	if err != nil {
		t.Fatal(err)
	}
	if int(spec.Maps["buffer_bindings"].ValueSize) != binary.Size(bufferBinding{}) {
		t.Fatal("buffer binding geometry differs from Go serialization")
	}
	if int(spec.Maps["buffer_anchors"].ValueSize) != binary.Size(bufferAnchor{}) {
		t.Fatal("buffer anchor geometry differs from Go memory accounting")
	}
	if int(spec.Maps["buffer_states"].ValueSize) != binary.Size(bufferFar{}) {
		t.Fatal("buffer FAR geometry differs from Go serialization")
	}
}
