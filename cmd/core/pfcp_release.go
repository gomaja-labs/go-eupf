// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

// AssociationCleanupTimeout bounds retries after the first rule-cleanup failure.
// Ownership and resource IDs remain reserved until every deletion commits.
const AssociationCleanupTimeout = 3 * time.Second

// AssociationReleaseTimeout derives the graceful period from configured T1/N1,
// rounded up to the IE's two-second units, with a two-to-eight-second bound.
// AssociationReleaseWaitTimeout adds the delivery window; process shutdown
// reserves a further four seconds for listener and map teardown.
// TS 29.244 V20.1.0 clauses 6.2.7.3.1 and 8.2.78.
func (conn *PfcpConnection) AssociationReleaseTimeout() time.Duration {
	if conn == nil {
		return 0
	}
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	return conn.releasePeriod()
}
func (conn *PfcpConnection) releasePeriod() time.Duration {
	interval, retries := conn.requestPolicy(message.MsgTypeAssociationUpdateRequest)
	window := interval * time.Duration(retries+1)
	unit := 2 * time.Second
	return min(8*time.Second, max(unit, ((window+unit-1)/unit)*unit))
}

// AssociationReleaseWaitTimeout bounds delivery attempts plus the CP's full
// advertised period. TS 29.244 V20.1.0 clauses 6.2.7.3.2 and 6.4.
func (conn *PfcpConnection) AssociationReleaseWaitTimeout() time.Duration {
	if conn == nil {
		return 0
	}
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	interval, retries := conn.requestPolicy(message.MsgTypeAssociationUpdateRequest)
	return interval*time.Duration(retries+1) + conn.releasePeriod()
}

// AssociationRelease tracks exactly the associations present at initiation.
// A management release can finish even after a new association is admitted.
type AssociationRelease struct {
	conn         *PfcpConnection
	associations []*NodeAssociation
}

// Done reports whether every original association has left the registry.
func (release *AssociationRelease) Done() bool {
	if release == nil {
		return true
	}
	release.conn.stateMu.RLock()
	defer release.conn.stateMu.RUnlock()
	for _, assoc := range release.associations {
		if release.conn.associationByID(assoc.ID) == assoc {
			return false
		}
	}
	return true
}

// Err reports a terminal data-plane cleanup failure.
func (release *AssociationRelease) Err() error {
	if release == nil {
		return nil
	}
	return release.conn.FatalError()
}

type admittedRequest struct {
	wire   []byte
	typ    uint8
	peer   *net.UDPAddr
	socket *net.UDPConn
	trace  bool
}

func (conn *PfcpConnection) sendAdmitted(requests []admittedRequest) error {
	var result error
	for _, request := range requests {
		if err := conn.sendEncodedAtSocket(request.wire, request.typ, request.peer, request.trace, request.socket); err != nil {
			result = errors.Join(result, err)
			log.Warn().Err(err).Str("peer", request.peer.String()).Msg("Send association release indication; reliable delivery retains it")
		}
		conn.recordReleaseTransmission(request.wire)
	}
	return result
}

func (conn *PfcpConnection) startAssociationRelease(id string, trace bool) error {
	conn.stateMu.Lock()
	assoc := conn.associationByID(id)
	if assoc == nil {
		conn.stateMu.Unlock()
		return errNoEstablishedAssociation
	}
	request, err := conn.prepareAssociationReleaseLocked(assoc, time.Now(), trace)
	conn.stateMu.Unlock()
	if request != nil {
		err = errors.Join(err, conn.sendAdmitted([]admittedRequest{*request}))
	}
	return err
}
func (conn *PfcpConnection) prepareAssociationReleaseLocked(assoc *NodeAssociation, now time.Time, trace bool) (*admittedRequest, error) {
	if assoc.releaseRequestSent || assoc.cleaning {
		return nil, nil
	}
	period := conn.releasePeriod()
	if assoc.releaseDeadline.IsZero() {
		interval, retries := conn.requestPolicy(message.MsgTypeAssociationUpdateRequest)
		assoc.releaseDeadline = now.Add(interval*time.Duration(retries+1) + period)
	}
	assoc.releaseRetryAt = now.Add(100 * time.Millisecond)
	// The association stays established after Update completion. Only CP Release
	// or expiry of this advertised period starts cleanup (6.2.7.3.1 / 6.2.8).
	request := message.NewAssociationUpdateRequest(0, conn.profile.NodeID(conn.nodeId), ie.NewPFCPAssociationReleaseRequest(1, 0), ie.NewGracefulReleasePeriod(period))
	peer, err := net.ResolveUDPAddr("udp", assoc.endpoint)
	if err != nil {
		return nil, err
	}
	socket := conn.socket()
	wire, err := conn.prepareRequestContext(request, peer, trace, socket, assoc.Addr, assoc, 0)
	if err != nil {
		return nil, err
	}
	conn.transport.mu.Lock()
	conn.transport.pending[request.Sequence()].releasePeriod = period
	conn.transport.mu.Unlock()
	interval, retries := conn.requestPolicy(message.MsgTypeAssociationUpdateRequest)
	assoc.releaseDeadline = time.Now().Add(interval*time.Duration(retries+1) + period)
	assoc.releaseRequestSent = true
	return &admittedRequest{wire, request.MessageType(), peer, socket, trace}, nil
}

func (conn *PfcpConnection) serviceReleasesLocked(now time.Time) []admittedRequest {
	var outgoing []admittedRequest
	// One detached batch per maintenance pass releases stateMu between batches.
	// Rotate the queue so successive replacements cannot starve an older one.
	if len(conn.retiredAssociations) > 0 {
		assoc := conn.retiredAssociations[0]
		if !now.Before(assoc.cleanupNext) {
			conn.cleanupAssociationLocked(assoc, now)
		}
		if len(conn.retiredAssociations) > 1 && conn.retiredAssociations[0] == assoc {
			copy(conn.retiredAssociations, conn.retiredAssociations[1:])
			conn.retiredAssociations[len(conn.retiredAssociations)-1] = assoc
		}
	}
	for _, assoc := range conn.NodeAssociations {
		if assoc.cleaning {
			if !now.Before(assoc.cleanupNext) {
				conn.cleanupAssociationLocked(assoc, now)
			}
			continue
		}
		if assoc.releaseDeadline.IsZero() {
			continue
		}
		if !now.Before(assoc.releaseDeadline) {
			conn.beginAssociationCleanupLocked(assoc, now)
			continue
		}
		if !assoc.releaseRequestSent && !now.Before(assoc.releaseRetryAt) {
			request, err := conn.prepareAssociationReleaseLocked(assoc, now, true)
			if err != nil {
				log.Warn().Err(err).Str("node", assoc.ID).Msg("Association release indication awaits originated-request capacity")
			}
			if request != nil {
				outgoing = append(outgoing, *request)
			}
		}
	}
	return outgoing
}

// TS 29.244 V20.1.0 clause 6.2.8.3: accept CP Release and delete its
// sessions. The bounded retry/fatal policy retains IDs on data-plane failure.
func (conn *PfcpConnection) beginAssociationCleanupLocked(assoc *NodeAssociation, now time.Time) {
	if assoc.cleaning {
		return
	}
	assoc.cleaning = true // Admission stops before the Release Response.
	assoc.cleanupNext = now
	if conn.ResourceManager.ShuttingDown() || len(assoc.Sessions) == 0 {
		conn.finishAssociationCleanupLocked(assoc)
	}
}
func (conn *PfcpConnection) finishAssociationCleanupLocked(assoc *NodeAssociation) {
	if assoc.retired {
		for i, current := range conn.retiredAssociations {
			if current == assoc {
				copy(conn.retiredAssociations[i:], conn.retiredAssociations[i+1:])
				conn.retiredAssociations[len(conn.retiredAssociations)-1] = nil
				conn.retiredAssociations = conn.retiredAssociations[:len(conn.retiredAssociations)-1]
				break
			}
		}
		return
	}
	if !conn.ResourceManager.ShuttingDown() {
		conn.indexAssociation(assoc, -1)
	}
	for key, current := range conn.NodeAssociations {
		if current == assoc {
			delete(conn.NodeAssociations, key)
			break
		}
	}
	conn.forgetPeer(assoc.ID)
	if len(conn.NodeAssociations) == 0 {
		conn.releasing = false
	}
}

// TS 29.244 V20.1.0 clause 6.2.6.2.2; TS 23.527 V20.0.0 clause
// 4.4.2.1: contexts become invalid before their asynchronous rule reclamation.
func (conn *PfcpConnection) retireAssociationLocked(assoc *NodeAssociation) {
	if len(assoc.Sessions) == 0 {
		return
	}
	assoc.retired, assoc.cleaning = true, true
	assoc.cleanupNext = time.Time{}
	conn.retiredAssociations = append(conn.retiredAssociations, assoc)
	PfcpCleanupPending.Add(float64(len(assoc.Sessions)))
}
func (conn *PfcpConnection) cleanupAssociationLocked(assoc *NodeAssociation, now time.Time) {
	if conn.terminalError != nil {
		return
	}
	assoc.cleanupAttempts++
	batch := 0
	attempt := func(id uint64, session *Session) {
		batch++
		if err := conn.DeleteSession(session); err != nil {
			failure := assoc.cleanupFailures[id]
			if failure.first.IsZero() {
				failure.first = maxTime(now, time.Now())
			}
			failure.attempts++
			failure.err = err
			delay := 100 * time.Millisecond
			for n := uint32(1); n < failure.attempts && delay < 500*time.Millisecond; n++ {
				delay = min(500*time.Millisecond, delay*2)
			}
			failure.next = maxTime(now, time.Now()).Add(delay)
			if assoc.cleanupFailures == nil {
				assoc.cleanupFailures = make(map[uint64]cleanupFailure)
			}
			assoc.cleanupFailures[id] = failure
			assoc.cleanupError = err
			if now.Sub(failure.first) >= AssociationCleanupTimeout {
				conn.cleanupFailedLocked(assoc)
			}
			log.Error().Err(err).Str("node", assoc.ID).Uint64("session", id).Uint32("attempt", assoc.cleanupAttempts).Msg("Rule cleanup failed; retain session ownership and IDs")
		} else {
			conn.forgetSession(assoc, id)
		}
	}
	// Retry failed sessions first so a large healthy backlog cannot starve them.
	for id, failure := range assoc.cleanupFailures {
		if batch >= 64 || conn.terminalError != nil {
			break
		}
		if !now.Before(failure.next) {
			attempt(id, assoc.Sessions[id])
		}
	}
	for id, session := range assoc.Sessions {
		if batch >= 64 || conn.terminalError != nil {
			break
		}
		if _, failed := assoc.cleanupFailures[id]; !failed {
			attempt(id, session)
		}
	}
	if len(assoc.Sessions) == 0 {
		conn.finishAssociationCleanupLocked(assoc)
		return
	}
	assoc.cleanupNext = time.Time{}
	if len(assoc.cleanupFailures) == len(assoc.Sessions) {
		for _, failure := range assoc.cleanupFailures {
			if assoc.cleanupNext.IsZero() || failure.next.Before(assoc.cleanupNext) {
				assoc.cleanupNext = failure.next
			}
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func (conn *PfcpConnection) cleanupFailedLocked(assoc *NodeAssociation) {
	if conn.terminalError != nil {
		return
	}
	err := fmt.Errorf("association %s rule cleanup exceeded %s with %d sessions still reserved: %w", assoc.ID, AssociationCleanupTimeout, len(assoc.Sessions), errors.Join(assoc.cleanupError, errors.New("rule cleanup deadline reached")))
	conn.terminalError = err
	for id := range assoc.Sessions {
		log.Error().Err(err).Uint64("session", id).Msg("Unremoved rules require process restart; session IDs remain reserved")
	}
	if conn.failures == nil {
		conn.failures = make(chan error, 1)
	}
	select {
	case conn.failures <- err:
	default:
	}
}

// Failures notifies the process supervisor of terminal rule cleanup failure.
// A nil optional connection returns a disabled select channel.
func (conn *PfcpConnection) Failures() <-chan error {
	if conn == nil {
		return nil
	}
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if conn.failures == nil {
		conn.failures = make(chan error, 1)
	}
	return conn.failures
}

// FatalError reports a terminal cleanup failure without consuming its notification.
func (conn *PfcpConnection) FatalError() error {
	if conn == nil {
		return nil
	}
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	return conn.terminalError
}

// Closing stops receive-loop maintenance, so finish bounded cleanup here too.
func (conn *PfcpConnection) cleanupBeforeClose() {
	if conn.ResourceManager.ShuttingDown() {
		return
	}
	conn.DeleteAllAssociations()
	for conn.cleanupPending() && conn.FatalError() == nil {
		time.Sleep(25 * time.Millisecond)
		conn.stateMu.Lock()
		conn.serviceReleasesLocked(time.Now())
		conn.stateMu.Unlock()
	}
}

func (conn *PfcpConnection) cleanupPending() bool {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	return len(conn.NodeAssociations) > 0 || len(conn.retiredAssociations) > 0
}

// BeginShutdown latches Setup refusal across the shared process resource domain.
// TS 29.244 V20.1.0 clauses 6.2.6 and 6.2.7.3.1.
func (conn *PfcpConnection) BeginShutdown() {
	if conn == nil {
		return
	}
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	conn.ResourceManager.BeginShutdown()
	conn.transport.mu.Lock()
	for seq, request := range conn.transport.pending {
		if request.typ == message.MsgTypeAssociationSetupRequest {
			conn.completeRequestLocked(request, requestResult{outcome: requestCanceled, err: errors.New("process shutting down")})
			conn.transport.deletePending(seq)
		}
	}
	conn.transport.mu.Unlock()
	for _, assoc := range conn.NodeAssociations {
		if assoc.cleaning {
			conn.finishAssociationCleanupLocked(assoc)
		}
	}
}

// CurrentRelease returns the immutable membership selected by the latest release.
func (conn *PfcpConnection) CurrentRelease() *AssociationRelease {
	if conn == nil {
		return nil
	}
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	return conn.release
}

func (conn *PfcpConnection) recordReleaseTransmission(wire []byte) {
	if len(wire) < 8 || wire[1] != message.MsgTypeAssociationUpdateRequest {
		return
	}
	// Node header sequence field: TS 29.244 V20.1.0 clause 7.2.2.2.
	sequence := uint32(wire[4])<<16 | uint32(wire[5])<<8 | uint32(wire[6])
	conn.transport.mu.Lock()
	defer conn.transport.mu.Unlock()
	if request := conn.transport.pending[sequence]; request != nil && request.releasePeriod > 0 {
		request.lastSent = time.Now()
	}
}
