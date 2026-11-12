// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"container/list"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

var errTransactionCapacity = errors.New("PFCP transaction capacity exhausted")

// transportState owns reliable-delivery state under mu. No network I/O occurs
// under mu. The connection receive loop calls serviceTransactions; it does not
// create a goroutine or timer for each request. TS 29.244 V20.1.0 clause 6.4.
type transportState struct {
	mu              sync.Mutex
	next            uint32
	pending         map[uint32]*pendingRequest
	responses       map[requestKey]cachedResponse
	bytes           int
	pendingBytes    int
	responseExpiry  list.List
	responseBudgets map[string]*responseBudget
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
	index   *responseIndex
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
	upFeatures  []byte
	remoteSEID  uint64
	localSEID   uint64
	onComplete  func(requestResult)
	completed   bool
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
	entity, association, localSEID := conn.outgoingContext(msg, peer.IP.String())
	return conn.prepareRequestContext(msg, peer, trace, socket, entity, association, localSEID)
}

// prepareRequestContext admits reliable delivery using an already resolved
// session context. Report producers may call it while holding stateMu.
func (conn *PfcpConnection) prepareRequestContext(msg message.Message, peer *net.UDPAddr, trace bool, socket *net.UDPConn, entity string, association *NodeAssociation, localSEID uint64) ([]byte, error) {
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
	if setup, ok := msg.(*message.AssociationSetupRequest); ok {
		if features, err := setup.UPFunctionFeatures.UPFunctionFeatures(); err == nil {
			state.pending[state.next].upFeatures = append([]byte(nil), features...)
		}
	}
	request := state.pending[state.next]
	request.remoteSEID = msg.SEID()
	request.localSEID = localSEID
	request.onComplete = conn.originatorCompletion(request)
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
	conn.stateMu.Lock()
	conn.completeRequestLocked(req, requestResult{outcome: requestTimeout, err: errRequestTimeout})
	conn.stateMu.Unlock()
	if req.typ == message.MsgTypeHeartbeatRequest {
		conn.heartbeatFailed(req.associationID(), req.association)
	}
}

// requestResult is the one terminal notification contract for every originator.
// Callbacks execute exactly once under stateMu and may neither wait nor perform
// network I/O or acquire transport.mu. TS 29.244 V20.1.0 clauses 6.4, 7.6.1,
// 7.6.3 and 7.6.6.
type requestOutcome string

const (
	requestAccepted requestOutcome = "accepted"
	requestRejected requestOutcome = "rejected"
	requestInvalid  requestOutcome = "invalid response"
	requestTimeout  requestOutcome = "no response"
	requestCanceled requestOutcome = "canceled"
)

var errRequestTimeout = errors.New("PFCP request retry budget exhausted")

type requestResult struct {
	outcome  requestOutcome
	response message.Message
	err      error
}

func (conn *PfcpConnection) completeRequestLocked(req *pendingRequest, result requestResult) {
	if req == nil || req.completed {
		return
	}
	req.completed = true
	if req.onComplete != nil {
		req.onComplete(result)
	}
}
func (conn *PfcpConnection) originatorCompletion(req *pendingRequest) func(requestResult) {
	return func(result requestResult) {
		if result.err != nil {
			log.Warn().Err(result.err).Str("peer", req.peer.String()).Str("procedure", message.MessageTypeName(req.typ)).Str("outcome", string(result.outcome)).Uint64("remote_seid", req.remoteSEID).Msg("PFCP requesting procedure completed")
		}
		if req.typ == message.MsgTypeAssociationSetupRequest {
			conn.lastSetupOutcome = result.outcome
			for _, node := range conn.nodes {
				if node.getAddress() != req.peer.IP.String() {
					continue
				}
				if conn.setupRetryAt == nil {
					conn.setupRetryAt = make(map[string]time.Time)
				}
				if result.outcome == requestAccepted {
					delete(conn.setupRetryAt, node.getAddress())
				} else {
					conn.setupRetryAt[node.getAddress()] = time.Now().Add(conn.setupInterval())
				}
			}
			return
		}
		assoc := conn.associationByID(req.associationID())
		if assoc == nil || assoc != req.association {
			return
		}
		if assoc.lastOutcomes == nil {
			assoc.lastOutcomes = make(map[uint8]requestOutcome)
		}
		assoc.lastOutcomes[req.typ] = result.outcome
		switch req.typ {
		case message.MsgTypeHeartbeatRequest:
			conn.finishProbeLocked(req)
		case message.MsgTypeSessionReportRequest:
			// Bind completion to the original UP session, even when the CP
			// reuses its SEID after deletion (TS 29.244 V20.1.0 clause 6.3.5).
			session := assoc.Sessions[req.localSEID]
			if session == nil || session.RemoteSEID != req.remoteSEID {
				return
			}
			if assoc.reportFailures == nil {
				assoc.reportFailures = make(map[uint64]requestOutcome)
			}
			if result.outcome == requestAccepted {
				delete(assoc.reportFailures, req.localSEID)
			} else {
				assoc.reportFailures[req.localSEID] = result.outcome
			}
		case message.MsgTypeAssociationUpdateRequest:
			// Update completion never substitutes for the CP Release procedure (6.2.7.3.1).
		}
	}
}
func responseResult(msg message.Message, err error) requestResult {
	result := requestResult{outcome: requestAccepted, response: msg, err: err}
	if err == nil {
		return result
	}
	result.outcome = requestInvalid
	if msg.MessageType() == message.MsgTypeVersionNotSupportedResponse {
		result.outcome = requestRejected
		return result
	}
	var cause *ie.IE
	switch value := msg.(type) {
	case *message.AssociationSetupResponse:
		cause = value.Cause
	case *message.AssociationUpdateResponse:
		cause = value.Cause
	case *message.AssociationReleaseResponse:
		cause = value.Cause
	case *message.SessionReportResponse:
		cause = value.Cause
	}
	if value, e := cause.Cause(); e == nil && value != ie.CauseRequestAccepted {
		result.outcome = requestRejected
	}
	return result
}

// minimumReplayWindow is local policy, not a peer-advertised N1/T1. TS 29.244
// V20.1.0 clause 6.4 specifies retransmission but no numeric retention window.
const minimumReplayWindow = 20 * time.Second

// One connection-wide accounting bound includes encoded responses plus a
// conservative metadata charge per entry; associations never multiply it.
const responseByteBudget = 16 << 20
const responseMetadataBytes = 1024
const responseReservation = 65535 + responseMetadataBytes + 512

type responseBudget struct {
	host    string // Association Node ID; host only in isolated index tests.
	entries list.List
	bytes   int
}
type responseIndex struct {
	key                    requestKey
	created, expires       time.Time
	budget                 *responseBudget
	element, expiryElement *list.Element
	size                   int
}

// Both indexes are intrusive lists: expiration and per-association invalidation
// unlink each entry in O(1). The retention interval is constant per connection,
// so insertion order is also expiration order. No stale accounting remains.
func (state *transportState) removeResponse(e *responseIndex) {
	state.bytes -= e.size
	delete(state.responses, e.key)
	state.responseExpiry.Remove(e.expiryElement)
	e.budget.entries.Remove(e.element)
	e.budget.bytes -= e.size
	if e.budget.entries.Len() == 0 {
		delete(state.responseBudgets, e.budget.host)
	}
}
func (conn *PfcpConnection) expireResponsesLocked(now time.Time) {
	state := &conn.transport
	for front := state.responseExpiry.Front(); front != nil; front = state.responseExpiry.Front() {
		e := front.Value.(*responseIndex)
		if now.Before(e.expires) {
			break
		}
		state.removeResponse(e)
	}
}

func responseOwner(key requestKey, owners []string) string {
	if len(owners) > 0 {
		return owners[0]
	}
	host, _, _ := net.SplitHostPort(key.peer)
	return host
}
func (conn *PfcpConnection) cachedReply(key requestKey, digest [32]byte, owners ...string) ([]byte, bool, error) {
	return conn.cachedReplyAt(key, digest, time.Now(), owners...)
}
func (conn *PfcpConnection) cachedReplyAt(key requestKey, digest [32]byte, now time.Time, owners ...string) ([]byte, bool, error) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	conn.expireResponsesLocked(now)
	key.digest = digest
	if entry, ok := state.responses[key]; ok {
		return entry.wire, true, nil
	}
	owner := responseOwner(key, owners)
	if owner == "" {
		return nil, false, nil
	}
	for len(state.responses) >= conn.transactionLimit() || state.bytes+responseReservation > responseByteBudget {
		victim := conn.replayVictimLocked(owner, now)
		if victim == nil {
			return nil, true, errTransactionCapacity
		}
		state.removeResponse(victim)
	}
	return nil, false, nil
}

// An association below both fair shares can reclaim eligible old entries from
// the association most above its share. Otherwise it can replace only its own
// old entries. Protected entries always win over new work (clause 6.4).
func (conn *PfcpConnection) replayVictimLocked(owner string, now time.Time) *responseIndex {
	state := &conn.transport
	peers := len(conn.NodeAssociations)
	if conn.associationByID(owner) == nil {
		peers++
	}
	peers = max(1, peers)
	entryShare := max(1, (conn.transactionLimit()+peers-1)/peers)
	byteShare := responseByteBudget / peers
	own := state.responseBudgets[owner]
	below := own == nil || own.entries.Len() < entryShare && own.bytes < byteShare
	var victim *responseIndex
	greatest := float64(0)
	for id, budget := range state.responseBudgets {
		if id != owner && !below {
			continue
		}
		e := budget.entries.Front().Value.(*responseIndex)
		if now.Sub(e.created) < minimumReplayWindow {
			continue
		}
		pressure := max(float64(budget.entries.Len())/float64(entryShare), float64(budget.bytes)/float64(byteShare))
		if id != owner && pressure <= 1 {
			continue
		}
		if victim == nil || pressure > greatest || pressure == greatest && e.created.Before(victim.created) {
			victim, greatest = e, pressure
		}
	}
	return victim
}

// The caller holds stateMu across admission, execution and insertion. Reserve
// the largest possible encoded reply before executing a request. Unknown peers
// never insert; successful initial Setup is charged to its new association.
func (conn *PfcpConnection) cacheReply(key requestKey, digest [32]byte, wire []byte, context ...string) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.responses == nil {
		state.responses = make(map[requestKey]cachedResponse)
	}
	if state.responseBudgets == nil {
		state.responseBudgets = make(map[string]*responseBudget)
	}
	key.digest = digest
	if old, ok := state.responses[key]; ok {
		state.removeResponse(old.index)
	}
	owner := responseOwner(key, nil)
	entity := ""
	if len(context) > 0 {
		entity = context[0]
	}
	if len(context) > 1 {
		owner = context[1]
	}
	budget := state.responseBudgets[owner]
	if budget == nil {
		budget = &responseBudget{host: owner}
		state.responseBudgets[owner] = budget
	}
	ttl := conn.responseRetention
	if ttl <= 0 {
		ttl = time.Minute
	}
	now := time.Now()
	cost := len(wire) + len(key.peer) + len(entity) + responseMetadataBytes
	e := &responseIndex{key: key, created: now, expires: now.Add(ttl), budget: budget, size: cost}
	e.element = budget.entries.PushBack(e)
	e.expiryElement = state.responseExpiry.PushBack(e)
	budget.bytes += cost
	state.responses[key] = cachedResponse{wire: wire, expires: e.expires, entity: entity, index: e}
	state.bytes += cost
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
	assoc := conn.GetAssociation(req.associationID())
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
	conn.completeRequestLocked(req, requestResult{outcome: requestInvalid, err: err})
	conn.stateMu.Unlock()
	log.Warn().Err(err).Str("peer", peer.String()).Str("message", message.MessageTypeName(typ)).Msg("Invalid matched PFCP response")
}

func (req *pendingRequest) associationID() string {
	if req.association != nil {
		return req.association.ID
	}
	return req.peer.IP.String()
}
