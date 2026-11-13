package core

import (
	"fmt"
	"github.com/gomaja-labs/go-pfcp/message"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
)

// This opt-in probe measures retained state, independently of Go's GC goal or
// the process/container resident footprint. Real binary load covers those too.
func TestReplayOutcomeHeapProfile(t *testing.T) {
	path := os.Getenv("EUPF_REPLAY_HEAP")
	if path == "" {
		t.Skip("set EUPF_REPLAY_HEAP to retain the heap calibration")
	}
	for _, holders := range []int{1, 1024} {
		t.Run(fmt.Sprint(holders), func(t *testing.T) {
			conn := newProtocolConnection(t)
			owners := make([]string, holders)
			for n := range owners {
				owners[n] = fmt.Sprintf("cp-%d.example", n)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			const count = 120000
			for n := range count {
				// The real receive path allocates its source/entity strings too.
				peer := fmt.Sprintf("%s:8805", net.IPv4(198, 18, 0, 1).String())
				entity := net.IPv4(198, 18, 0, 1).String()
				conn.cacheReply(requestKey{peer: peer, sequence: uint32(n), typ: message.MsgTypeSessionModificationRequest}, [32]byte{}, make([]byte, 80), entity, owners[n%holders])
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			delta := after.HeapAlloc - before.HeapAlloc
			t.Logf("holders=%d entries=%d retained_heap_bytes=%d bytes_per_outcome=%.2f accounted_bytes=%d", holders, len(conn.transport.responses), delta, float64(delta)/count, conn.transport.bytes)
			if int64(delta) > int64(conn.transport.bytes) {
				t.Fatal("replay accounting understates measured retained heap")
			}
			f, err := os.Create(fmt.Sprintf("%s-%d", path, holders))
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
		})
	}
}
