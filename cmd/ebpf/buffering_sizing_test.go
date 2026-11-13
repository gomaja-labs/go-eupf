//go:build linux

package ebpf

import (
	"encoding/binary"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
)

func TestBufferMapSizingMatchesTheMemoryPlan(t *testing.T) {
	spec, err := LoadIpEntrypoint()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Maps["buffer_anchors"].MaxEntries != config.BufferSessionLimit || int(spec.Maps["buffer_anchors"].ValueSize) != binary.Size(bufferAnchor{}) {
		t.Fatal("buffer anchor geometry differs from Go memory accounting")
	}
}
