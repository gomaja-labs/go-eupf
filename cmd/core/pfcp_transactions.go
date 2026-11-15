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

	"github.com/gomaja-labs/go-eupf/cmd/core/service"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

var errTransactionCapacity = errors.New("PFCP transaction capacity exhausted")

// transportState owns reliable-delivery state under mu. No network I/O occurs
// under mu. The connection receive loop calls serviceTransactions; it does not
// create a goroutine or timer for each request. TS 29.244 V20.1.0 clause 6.4.
type transportState struct {
	replay          *service.ReplayBudget
	replayEndpoint  uint64
	mu              sync.Mutex
	next            uint32
	pending         map[uint32]*pendingRequest
	responses       map[requestKey]*responseIndex
	bytes           int
	pendingBytes    int
	responseExpiry  responseList
	responseBudgets map[string]*responseBudget
}
type requestKey struct {
	peer     string
	sequence uint32
	typ      uint8
	digest   [32]byte
}
type pendingRequest struct {
	localRelease           *localSessionRelease
	localReleaseReport     bool
	localReleaseLast       bool
	wire                   []byte
	peer                   *net.UDPAddr
	typ                    uint8
	retryAt                time.Time
	lastSent               time.Time
	releasePeriod          time.Duration
	interval               time.Duration
	remaining              uint32
	trace                  bool
	entity                 string
	association            *NodeAssociation
	socket                 *net.UDPConn
	upFeatures             []byte
	remoteSEID             uint64
	localSEID              uint64
	usage                  []reportedUsage
	downlink               *reportedDownlink
	reportBufferState      *downlinkNotifications
	reportBufferGeneration uint64
	reportBufferRevision   uint64
	bufferUpdate           *bufferReportUpdate
	onComplete             func(requestResult)
	completed              bool
	completedOutcome       requestOutcome
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
	if msg.SEID() != 0 {
		return nil, errors.New("session request requires an explicit local SEID")
	}
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	return conn.prepareRequestContext(msg, peer, trace, socket, peer.IP.String(), conn.GetAssociation(peer.IP.String()), 0)
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
	if msg.MessageType() == message.MsgTypeAssociationSetupRequest && (conn.ResourceManager.ShuttingDown() || conn.releasing) {
		return nil, errors.New("PFCP association admission stopped")
	}
	if state.pending == nil {
		state.pending = make(map[uint32]*pendingRequest)
	}
	if socket != conn.socket() {
		return nil, fmt.Errorf("PFCP local endpoint changed")
	}
	if len(state.pending) >= conn.originatedRequestLimit() || state.pendingBytes+msg.MarshalLen() > 16<<20 {
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
	state.pending[state.next] = &pendingRequest{wire: wire, peer: &copied, typ: msg.MessageType(), lastSent: time.Now(), retryAt: time.Now().Add(interval), interval: interval, remaining: retries, trace: trace, entity: entity, association: association, socket: socket}
	if setup, ok := msg.(*message.AssociationSetupRequest); ok {
		if features, err := setup.UPFunctionFeatures.UPFunctionFeatures(); err == nil {
			state.pending[state.next].upFeatures = append([]byte(nil), features...)
		}
	}
	request := state.pending[state.next]
	request.remoteSEID = msg.SEID()
	request.localSEID = localSEID
	if association != nil && msg.MessageType() == message.MsgTypeSessionReportRequest {
		if session := association.Sessions[localSEID]; session != nil {
			request.reportBufferState = session.downlink
			request.reportBufferRevision = session.bufferControlRevision
			if session.downlink != nil {
				request.reportBufferGeneration = session.downlink.generation
			}
		}
	}
	request.onComplete = conn.originatorCompletion(request)
	state.pendingBytes += len(wire)
	return wire, nil
}
func (conn *PfcpConnection) transactionLimit() int {
	if conn.maxReplayEntries == 0 {
		return 131072
	}
	return int(conn.maxReplayEntries)
}
func (conn *PfcpConnection) originatedRequestLimit() int {
	if conn.maxOriginatedRequests == 0 {
		return 4096
	}
	return int(conn.maxOriginatedRequests)
}
func (conn *PfcpConnection) replayByteLimit() int {
	if conn.replayMemoryMiB == 0 {
		return 128 << 20
	}
	return int(conn.replayMemoryMiB) << 20
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
		req.lastSent = now
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
		if req.releasePeriod > 0 {
			conn.recordReleaseTransmission(req.wire)
		}
	}
	for _, req := range failed {
		conn.requestFailed(req)
	}
	conn.flushReportRetries()
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
	req.completedOutcome = result.outcome
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
		failedReport := req.typ == message.MsgTypeSessionReportRequest && result.outcome != requestAccepted
		if failedReport {
			PfcpReportFailures.WithLabelValues(string(result.outcome)).Inc()
		}
		if req.localRelease != nil {
			conn.completeLocalReleaseRequestLocked(req, result)
			return
		}
		assoc := conn.associationByID(req.associationID())
		if assoc == nil || assoc != req.association {
			if failedReport {
				recordUndeliveredUsage(req, "association removed or replaced")
			}
			return
		}
		switch req.typ {
		case message.MsgTypeHeartbeatRequest:
			conn.finishProbeLocked(req)
		case message.MsgTypeSessionReportRequest:
			// Bind completion to the original UP session. Its CP F-SEID can
			// change while delivery is pending (TS 29.244 V20.1.0 clauses
			// 6.3.3.3 and 6.3.5); that does not remove its URRs or usage debt.
			session := assoc.Sessions[req.localSEID]
			if session == nil {
				if failedReport {
					recordUndeliveredUsage(req, "session removed or replaced")
				}
				return
			}
			conn.completeReportLocked(req, session, result)
		case message.MsgTypeAssociationUpdateRequest:
			// TS 29.244 V20.1.0 clauses 6.2.7.3.2 and 6.4: an identical
			// retransmission grants the CP the full period from reception.
			if req.releasePeriod > 0 && !assoc.cleaning {
				start := req.lastSent
				if result.outcome == requestAccepted {
					start = time.Now()
				}
				assoc.releaseDeadline = start.Add(req.releasePeriod)
			}
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

// TS 29.244 V20.1.0 clause 6.4: every outcome remains protected for
// the entire operator-configured peer retransmission window.
const responseMetadataBytes = 640
const responseReservation = 65535 + responseMetadataBytes + 512

type responseBudget struct {
	host    string // Association Node ID; host only in isolated index tests.
	entries responseList
	bytes   int
}
type responseIndex struct {
	key                        requestKey
	wire                       []byte
	entity                     string
	created, expires           time.Time
	budget                     *responseBudget
	ownerPrevious, ownerNext   *responseIndex
	expiryPrevious, expiryNext *responseIndex
	size                       int
}

// responseList embeds both indexes in their existing cache entry, avoiding
// interface-valued list elements and their extra allocations and GC roots.
type responseList struct {
	head, tail *responseIndex
	count      int
}

func (l *responseList) Front() *responseIndex { return l.head }
func (l *responseList) Len() int              { return l.count }
func (l *responseList) append(e *responseIndex, expiry bool) {
	if expiry {
		e.expiryPrevious = l.tail
		e.expiryNext = nil
		if l.tail != nil {
			l.tail.expiryNext = e
		}
	} else {
		e.ownerPrevious = l.tail
		e.ownerNext = nil
		if l.tail != nil {
			l.tail.ownerNext = e
		}
	}
	if l.head == nil {
		l.head = e
	}
	l.tail = e
	l.count++
}
func (l *responseList) remove(e *responseIndex, expiry bool) {
	previous, next := e.ownerPrevious, e.ownerNext
	if expiry {
		previous, next = e.expiryPrevious, e.expiryNext
	}
	if previous == nil {
		l.head = next
	} else if expiry {
		previous.expiryNext = next
	} else {
		previous.ownerNext = next
	}
	if next == nil {
		l.tail = previous
	} else if expiry {
		next.expiryPrevious = previous
	} else {
		next.ownerPrevious = previous
	}
	if expiry {
		e.expiryPrevious, e.expiryNext = nil, nil
	} else {
		e.ownerPrevious, e.ownerNext = nil, nil
	}
	l.count--
}

// Both indexes are intrusive lists: expiration and per-association invalidation
// unlink each entry in O(1). The retention interval is constant per connection,
// so insertion order is also expiration order. No stale accounting remains.
func (state *transportState) removeResponse(e *responseIndex) {
	state.replay.Change(state.replayOwner(e.budget.host), -1, -e.size)
	state.unlinkResponse(e)
}
func (state *transportState) unlinkResponse(e *responseIndex) {
	state.bytes -= e.size
	delete(state.responses, e.key)
	state.responseExpiry.remove(e, true)
	e.budget.entries.remove(e, false)
	e.budget.bytes -= e.size
	if e.budget.entries.Len() == 0 {
		delete(state.responseBudgets, e.budget.host)
	}
}
func (conn *PfcpConnection) expireResponsesLocked(now time.Time) {
	state := &conn.transport
	for front := state.responseExpiry.Front(); front != nil; front = state.responseExpiry.Front() {
		e := front
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
	replay := conn.replayBudgetLocked()
	if state.replayEndpoint == 0 || !replay.Reserve(state.replayOwner(owner), responseReservation, conn.transactionLimit(), conn.replayByteLimit()) {
		PfcpReplayDrops.Inc()
		return nil, true, errTransactionCapacity
	}
	// Reserve before executing: independent endpoints cannot overbook the shared
	// budget while another endpoint is building its response.
	conn.cacheReplyLocked(key, nil, "", owner, true)
	return nil, false, nil
}

// The caller holds stateMu across admission, execution and insertion. Reserve
// the largest possible encoded reply before executing a request. Unknown peers
// never insert; successful initial Setup is charged to its new association.
func (conn *PfcpConnection) cacheReply(key requestKey, digest [32]byte, wire []byte, context ...string) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	key.digest = digest
	owner := responseOwner(key, nil)
	entity := ""
	if len(context) > 0 {
		entity = context[0]
	}
	if len(context) > 1 {
		owner = context[1]
	}
	conn.cacheReplyLocked(key, wire, entity, owner, false)
}

func (conn *PfcpConnection) cacheReplyLocked(key requestKey, wire []byte, entity, owner string, reserved bool) {
	state := &conn.transport
	budgetAccount := conn.replayBudgetLocked()
	if state.responses == nil {
		state.responses = make(map[requestKey]*responseIndex)
	}
	if state.responseBudgets == nil {
		state.responseBudgets = make(map[string]*responseBudget)
	}
	ttl := conn.responseRetention
	if ttl <= 0 {
		ttl = time.Minute
	}
	now := time.Now()
	cost := len(wire) + len(key.peer) + len(entity) + responseMetadataBytes
	if wire == nil {
		cost = responseReservation
	}
	if old, ok := state.responses[key]; ok {
		delta := cost - old.size
		budgetAccount.Change(state.replayOwner(owner), 0, delta)
		state.bytes += delta
		old.budget.bytes += delta
		old.wire, old.entity, old.created, old.expires, old.size = wire, entity, now, now.Add(ttl), cost
		state.responseExpiry.remove(old, true)
		state.responseExpiry.append(old, true)
		return
	}
	if !reserved {
		budgetAccount.Change(state.replayOwner(owner), 1, cost)
	}
	budget := state.responseBudgets[owner]
	if budget == nil {
		budget = &responseBudget{host: owner}
		state.responseBudgets[owner] = budget
	}
	e := &responseIndex{key: key, wire: wire, entity: entity, created: now, expires: now.Add(ttl), budget: budget, size: cost}
	budget.entries.append(e, false)
	state.responseExpiry.append(e, true)
	budget.bytes += cost
	state.responses[key] = e
	state.bytes += cost
}

func (conn *PfcpConnection) replayBudgetLocked() *service.ReplayBudget {
	state := &conn.transport
	if state.replay == nil {
		if conn.ResourceManager != nil {
			state.replay = conn.ResourceManager.ReplayBudget()
		} else {
			state.replay = &service.ReplayBudget{}
		}
		state.replayEndpoint = state.replay.NewEndpoint()
	}
	return state.replay
}

func (state *transportState) replayOwner(nodeID string) service.ReplayOwner {
	return service.ReplayOwner{Endpoint: state.replayEndpoint, NodeID: nodeID}
}

func (conn *PfcpConnection) discardReply(key requestKey, digest [32]byte) {
	conn.transport.mu.Lock()
	defer conn.transport.mu.Unlock()
	key.digest = digest
	if entry, ok := conn.transport.responses[key]; ok {
		conn.transport.removeResponse(entry)
	}
}

func (state *transportState) clearResponses() {
	for _, entry := range state.responses {
		state.removeResponse(entry)
	}
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
