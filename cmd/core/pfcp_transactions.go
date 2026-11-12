// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gomaja-labs/go-pfcp/message"
)

var errTransactionCapacity = errors.New("PFCP transaction capacity exhausted")

// transportState owns reliable-delivery state under mu. No network I/O occurs
// under mu. The connection receive loop calls serviceTransactions; it does not
// create a goroutine or timer for each request. TS 29.244 V20.1.0 clause 6.4.
type transportState struct {
	mu        sync.Mutex
	next      uint32
	pending   map[uint32]*pendingRequest
	responses map[requestKey]cachedResponse
	bytes     int
}
type requestKey struct {
	peer     string
	sequence uint32
	typ      uint8
}
type cachedResponse struct {
	digest  [32]byte
	wire    []byte
	expires time.Time
}
type pendingRequest struct {
	wire      []byte
	peer      *net.UDPAddr
	typ       uint8
	retryAt   time.Time
	interval  time.Duration
	remaining uint32
	trace     bool
}

func (conn *PfcpConnection) requestPolicy(typ uint8) (time.Duration, uint32) {
	interval, retries := conn.requestTimeout, conn.requestRetries
	if typ == message.MsgTypeHeartbeatRequest {
		interval, retries = conn.heartbeatTimeout, conn.heartbeatRetries
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return interval, retries
}
func (conn *PfcpConnection) prepareRequest(msg message.Message, peer *net.UDPAddr, trace bool) ([]byte, error) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.pending == nil {
		state.pending = make(map[uint32]*pendingRequest)
	}
	if len(state.pending) >= conn.transactionLimit() {
		return nil, errTransactionCapacity
	}
	// Sequence numbers are unique across the entire local endpoint, including
	// different peers, and wrap within the 24-bit wire field (clause 6.4).
	for {
		state.next = (state.next + 1) & 0xffffff
		if _, busy := state.pending[state.next]; !busy {
			break
		}
	}
	msg.SetSequenceNumber(state.next)
	wire := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(wire); err != nil {
		return nil, err
	}
	interval, retries := conn.requestPolicy(msg.MessageType())
	copied := *peer
	copied.IP = append(net.IP(nil), peer.IP...)
	state.pending[state.next] = &pendingRequest{wire: wire, peer: &copied, typ: msg.MessageType(), retryAt: time.Now().Add(interval), interval: interval, remaining: retries, trace: trace}
	return wire, nil
}
func (conn *PfcpConnection) transactionLimit() int {
	if conn.maxTransactions == 0 {
		return 4096
	}
	return int(conn.maxTransactions)
}

// matchResponse removes only a response for the same remote endpoint, sequence
// and procedure. Malformed matched responses also stop retries (clause 7.6.1).
func (conn *PfcpConnection) matchResponse(typ uint8, seq uint32, peer *net.UDPAddr) bool {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	req := state.pending[seq]
	if req == nil || req.peer.String() != peer.String() || (typ != req.typ+1 && typ != message.MsgTypeVersionNotSupportedResponse) {
		return false
	}
	delete(state.pending, seq)
	return true
}
func (conn *PfcpConnection) serviceTransactions(now time.Time) {
	state := &conn.transport
	state.mu.Lock()
	var resend []*pendingRequest
	var failed []*pendingRequest
	for seq, req := range state.pending {
		if now.Before(req.retryAt) {
			continue
		}
		if req.remaining == 0 {
			delete(state.pending, seq)
			failed = append(failed, req)
			continue
		}
		req.remaining--
		req.retryAt = now.Add(req.interval)
		resend = append(resend, req)
	}
	conn.expireResponsesLocked(now)
	state.mu.Unlock()
	for _, req := range resend {
		_ = conn.sendEncoded(req.wire, req.typ, req.peer, req.trace)
	}
	for _, req := range failed {
		conn.requestFailed(req)
	}
}
func (conn *PfcpConnection) requestFailed(req *pendingRequest) {
	if req.typ == message.MsgTypeHeartbeatRequest {
		conn.heartbeatFailed(req.peer.IP.String())
	}
}
func (conn *PfcpConnection) expireResponsesLocked(now time.Time) {
	for key, entry := range conn.transport.responses {
		if !now.Before(entry.expires) {
			conn.transport.bytes -= len(entry.wire)
			delete(conn.transport.responses, key)
		}
	}
}

// cachedReply is called while stateMu serializes application execution. A reused
// transaction ID with different content is discarded rather than re-executed.
func (conn *PfcpConnection) cachedReply(key requestKey, digest [32]byte) ([]byte, bool, error) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	conn.expireResponsesLocked(time.Now())
	if entry, ok := state.responses[key]; ok {
		if entry.digest != digest {
			return nil, true, fmt.Errorf("PFCP transaction ID reused with different content")
		}
		return entry.wire, true, nil
	}
	if len(state.responses) >= conn.transactionLimit() || state.bytes+65535 > 16<<20 {
		return nil, true, errTransactionCapacity
	}
	return nil, false, nil
}
func (conn *PfcpConnection) cacheReply(key requestKey, digest [32]byte, wire []byte) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.responses == nil {
		state.responses = make(map[requestKey]cachedResponse)
	}
	// Retention is local policy: clause 6.4 specifies no numeric lifetime. Never
	// evict a live response to admit work that could subsequently execute twice.
	ttl := conn.responseRetention
	if ttl <= 0 {
		ttl = time.Minute
	}
	state.responses[key] = cachedResponse{digest: digest, wire: wire, expires: time.Now().Add(ttl)}
	state.bytes += len(wire)
}
