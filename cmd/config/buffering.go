package config

import "fmt"

// BufferFrameBytes is the fixed Ethernet-frame payload class in the packet ring.
const BufferFrameBytes = 2048

// BufferingParameters holds effective process-wide packet pool settings.
type BufferingParameters struct{ Packets, PerSession, RetentionSeconds uint32 }

// Buffering resolves zero-valued programmatic configurations to startup defaults.
func (c *UpfConfig) Buffering() BufferingParameters {
	result := BufferingParameters{Packets: c.BufferPackets, PerSession: c.BufferPerSession, RetentionSeconds: c.BufferRetentionSeconds}
	if result.Packets == 0 {
		result.Packets = 4096
	}
	if result.PerSession == 0 {
		result.PerSession = 4
	}
	if result.RetentionSeconds == 0 {
		result.RetentionSeconds = 30
	}
	return result
}

// ValidateBuffering checks the allocation and retention bounds before startup.
func (c *UpfConfig) ValidateBuffering() error {
	p := c.Buffering()
	if p.Packets > 65536 {
		return fmt.Errorf("buffer_packets must not exceed 65536")
	}
	if p.PerSession > 64 || p.PerSession > p.Packets {
		return fmt.Errorf("buffer_per_session must be at most 64 and must fit buffer_packets")
	}
	if p.RetentionSeconds > 86400 {
		return fmt.Errorf("buffer_retention_seconds must not exceed 86400")
	}
	return nil
}

// BufferMemoryReserve accounts for measured retained heap with replacement/GC
// headroom. Linux/amd64 Go 1.27.4 profiles at N=4096 measured 148 bytes per
// packet descriptor/free index, 894 bytes per one-FAR owner, 284 bytes per FAR
// in a many-FAR owner, and 4555 bytes per FAR with all 65 notice identities.
// Each term is rounded up separately; payloads have one fixed allocation.
// A prepared one-packet profile added 122008 in-use bytes including probe
// overhead; round that complete small shape to 128 KiB before doubling it.
// See docs/pfcp-transport.md for the measured shapes and their limits.
func (c *UpfConfig) BufferMemoryReserve() int64 {
	p := c.Buffering()
	sessions, fars := c.bufferMetadataCapacity()
	const fixedRuntime = 128 << 10
	return 2*fixedRuntime + int64(p.Packets)*(BufferFrameBytes+2*160) +
		2*1024*sessions + 2*320*(2*fars) + 2*4608*fars
}

// BufferKernelMemoryReserve covers growing metadata independently of packet
// storage. Measured cgroup deltas at 1024 and 65535 sessions are rounded up to
// 320 bytes per session (anchor and wakeup) and 1152 per FAR lifetime; the
// lifetime map accommodates current and retiring versions. The FAR-slot binding
// map measured 104-108 kernel bytes per populated slot; the same 1152-byte
// rounding per lifetime covers that map alongside both live/retiring states.
// Empty maps and the
// fixed ring and continuation programs are part of the observed loaded baseline.
// A full N=4096 rendered-result map measured 4103 kernel bytes per packet;
// round to 4608 independently of the Go payload allocation.
func (c *UpfConfig) BufferKernelMemoryReserve() int64 {
	sessions, fars := c.bufferMetadataCapacity()
	// Deferred admission/render programs and the kernel conduit measured 2297856
	// kernel bytes at one packet. At 65536 slots the empty result hash adds
	// about 16 bytes/slot, within the 4608-vs-4103 per-packet rounding below.
	const deferredRuntime = 3 << 20
	return deferredRuntime + 320*sessions + 1152*(2*fars) + 4608*int64(c.Buffering().Packets)
}

func (c *UpfConfig) bufferMetadataCapacity() (sessions, fars int64) {
	sessions = int64(c.MaxSessions)
	if sessions == 0 {
		sessions = 65535
	}
	fars = int64(c.FarMapSize)
	if fars == 0 {
		fars = 2 * sessions
	}
	return sessions, fars
}

// UsageWindowMemoryReserve keeps the per-URR window timestamps and restored
// unreported window independent of the earlier session-model measurement. A
// retained-heap profile of 8192 one-URR maps measured a 384-byte increase per
// map over the same model without timestamps; reserve that worst sparse shape
// twice for replacement/GC. Dense maps use less per URR.
func (c *UpfConfig) UsageWindowMemoryReserve() int64 {
	capacity := uint64(c.UrrMapSize)
	if capacity == 0 {
		sessions := c.MaxSessions
		if sessions == 0 {
			sessions = 65535
		}
		capacity = 2 * uint64(sessions)
	}
	return int64(capacity) * (2 * 384)
}
