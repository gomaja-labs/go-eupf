package config

import "fmt"

// BufferFrameBytes is the fixed Ethernet-frame payload class in the packet ring.
const BufferFrameBytes = 2048

// BufferSessionLimit is the number of stable kernel buffering anchors.
const BufferSessionLimit = 1024

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

// BufferMemoryReserve accounts for the fixed payload pool, descriptors, and
// current/retiring lifetime metadata with GC headroom. Kernel ring and anchor
// pages are allocated at BPF load and are included in the measured baseline.
func (c *UpfConfig) BufferMemoryReserve() int64 {
	p := c.Buffering()
	sessions := c.MaxSessions
	if sessions == 0 {
		sessions = 65535
	}
	owners := min(sessions, uint32(BufferSessionLimit), p.Packets/p.PerSession)
	const descriptor = 256
	const ownerMetadata = 64 << 10
	return int64(p.Packets)*(BufferFrameBytes+2*descriptor) + int64(owners)*2*ownerMetadata
}

// UsageWindowMemoryReserve keeps the per-URR window timestamps and restored
// unreported window independent of the earlier session-model measurement.
func (c *UpfConfig) UsageWindowMemoryReserve() int64 {
	capacity := uint64(c.UrrMapSize)
	if capacity == 0 {
		sessions := c.MaxSessions
		if sessions == 0 {
			sessions = 65535
		}
		capacity = 2 * uint64(sessions)
	}
	return int64(capacity) * 128
}
