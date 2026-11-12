package core

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
)

func TestReplayOutcomeHeapProfile(t *testing.T) {
	path := os.Getenv("EUPF_REPLAY_HEAP")
	if path == "" {
		t.Skip("set EUPF_REPLAY_HEAP to retain the heap profile")
	}
	conn := newProtocolConnection(t)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const count = 120000
	for i := range count {
		peer := fmt.Sprintf("198.18.%d.%d:8805", (i/250)%250, i%250+1)
		conn.cacheReply(requestKey{peer: peer, sequence: uint32(i), typ: 7}, [32]byte{}, make([]byte, 80), "198.18.0.1", "cp.example")
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("entries=%d wire_bytes=80 retained_heap=%d bytes_per_outcome=%.2f accounted_bytes=%d", count, after.HeapAlloc-before.HeapAlloc, float64(after.HeapAlloc-before.HeapAlloc)/count, conn.transport.bytes)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.WriteHeapProfile(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(conn)
}
