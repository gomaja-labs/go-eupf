// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

var errTransactionCapacity = errors.New("PFCP transaction capacity exhausted")

// transportState owns reliable-delivery state under mu. No network I/O occurs
// under mu. The connection receive loop calls serviceTransactions; it does not
// create a goroutine or timer for each request. TS 29.244 V20.1.0 clause 6.4.
type transportState struct {
	mu           sync.Mutex
	next         uint32
	pending      map[uint32]*pendingRequest
	responses    map[requestKey]cachedResponse
	bytes        int
	pendingBytes int
}
type requestKey struct {
	peer     string
	sequence uint32
	typ      uint8
	digest   [32]byte
}
type cachedResponse struct {
	wire    []byte
	expires time.Time
	entity  string
}
type pendingRequest struct {
	wire        []byte
	peer        *net.UDPAddr
	typ         uint8
	retryAt     time.Time
	interval    time.Duration
	remaining   uint32
	trace       bool
	entity      string
	association *NodeAssociation
	socket      *net.UDPConn
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
func (conn *PfcpConnection) prepareRequest(msg message.Message, peer *net.UDPAddr, trace bool, socket *net.UDPConn) ([]byte, error) {
	entity, association := conn.outgoingContext(msg, peer.IP.String())
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	if conn.isClosed() {
		return nil, net.ErrClosed
	}
	if state.pending == nil {
		state.pending = make(map[uint32]*pendingRequest)
	}
	if socket != conn.socket() {
		return nil, fmt.Errorf("PFCP local endpoint changed")
	}
	if len(state.pending) >= conn.transactionLimit() || state.pendingBytes+msg.MarshalLen() > 16<<20 {
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
	if msg.MarshalLen() > 65535 {
		return nil, fmt.Errorf("PFCP request exceeds maximum UDP payload")
	}
	wire := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(wire); err != nil {
		return nil, err
	}
	interval, retries := conn.requestPolicy(msg.MessageType())
	copied := *peer
	copied.IP = append(net.IP(nil), peer.IP...)
	state.pending[state.next] = &pendingRequest{wire: wire, peer: &copied, typ: msg.MessageType(), retryAt: time.Now().Add(interval), interval: interval, remaining: retries, trace: trace, entity: entity, association: association, socket: socket}
	state.pendingBytes += len(wire)
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
	return conn.takeResponse(typ, seq, peer) != nil
}
func (conn *PfcpConnection) takeResponse(typ uint8, seq uint32, peer *net.UDPAddr) *pendingRequest {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	req := state.pending[seq]
	if req == nil || req.peer.String() != peer.String() || (typ != req.typ+1 && typ != message.MsgTypeVersionNotSupportedResponse) {
		return nil
	}
	state.deletePending(seq)
	return req
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
			state.deletePending(seq)
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
		PfcpRequestRetransmissions.WithLabelValues(message.MessageTypeName(req.typ)).Inc()
		if err := conn.sendEncodedAtSocket(req.wire, req.typ, req.peer, req.trace, req.socket); err != nil {
			log.Warn().Err(err).Str("peer", req.peer.String()).Str("message", message.MessageTypeName(req.typ)).Msg("PFCP retransmission failed")
		}
	}
	for _, req := range failed {
		conn.requestFailed(req)
	}
}
func (conn *PfcpConnection) requestFailed(req *pendingRequest) {
	PfcpRequestTimeouts.WithLabelValues(message.MessageTypeName(req.typ)).Inc()
	log.Warn().Str("peer", req.peer.String()).Str("message", message.MessageTypeName(req.typ)).Msg("PFCP request retry budget exhausted")
	if req.typ == message.MsgTypeHeartbeatRequest {
		conn.heartbeatFailed(req.peer.IP.String(), req.association)
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

// cachedReply is called while stateMu serializes application execution.
// Include the request fingerprint: clause 6.4 permits a completed sequence to
// be reused for another request, while an identical retransmission is replayed.
func (conn *PfcpConnection) cachedReply(key requestKey, digest [32]byte) ([]byte, bool, error) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	conn.expireResponsesLocked(time.Now())
	key.digest = digest
	if entry, ok := state.responses[key]; ok {
		return entry.wire, true, nil
	}
	if len(state.responses) >= conn.transactionLimit() || state.bytes+65535 > 16<<20 {
		return nil, true, errTransactionCapacity
	}
	return nil, false, nil
}
func (conn *PfcpConnection) cacheReply(key requestKey, digest [32]byte, wire []byte, entities ...string) {
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
	entity := ""
	if len(entities) > 0 {
		entity = entities[0]
	}
	key.digest = digest
	state.responses[key] = cachedResponse{wire: wire, expires: time.Now().Add(ttl), entity: entity}
	state.bytes += len(wire)
}

func defaultDuration(seconds, fallback uint32) time.Duration {
	if seconds == 0 {
		seconds = fallback
	}
	return time.Duration(seconds) * time.Second
}
func (conn *PfcpConnection) admitPeer(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if len(conn.allowedPeers) == 0 {
		return true
	}
	for _, prefix := range conn.allowedPeers {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (state *transportState) deletePending(seq uint32) {
	if req := state.pending[seq]; req != nil {
		state.pendingBytes -= len(req.wire)
		delete(state.pending, seq)
	}
}

func (conn *PfcpConnection) finishProbeLocked(req *pendingRequest) {
	if req == nil || req.typ != message.MsgTypeHeartbeatRequest {
		return
	}
	assoc := conn.GetAssociation(req.peer.IP.String())
	if assoc == nil || assoc != req.association {
		return
	}
	assoc.heartbeatInFlight = false
	assoc.nextHeartbeat = time.Now().Add(conn.heartbeatInterval())
}
func (conn *PfcpConnection) failResponse(typ uint8, seq uint32, peer *net.UDPAddr, err error) {
	req := conn.takeResponse(typ, seq, peer)
	if req == nil {
		return
	}
	conn.stateMu.Lock()
	conn.finishProbeLocked(req)
	conn.stateMu.Unlock()
	log.Warn().Err(err).Str("peer", peer.String()).Str("message", message.MessageTypeName(typ)).Msg("Invalid matched PFCP response")
}
