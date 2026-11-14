// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package ebpf

// RenderedBuffer is a completed packet rewrite and its resolved egress.
// Rendering alone never transmits a frame.
type RenderedBuffer struct {
	Frame          []byte
	Ifindex        uint32
	Action         uint32
	IngressIfindex uint32
}
