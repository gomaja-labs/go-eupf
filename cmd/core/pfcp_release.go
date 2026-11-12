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
// This leaves cleanup and HTTP shutdown within the process's 15-second deadline.
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
	if assoc.releaseRequestSent || !assoc.cleanupDeadline.IsZero() {
		return nil, nil
	}
	period := conn.releasePeriod()
	if !assoc.releaseDeadline.IsZero() {
		// A previously full originated queue can be retried while time remains.
		// Advertise no more than the remaining local grace period.
		period = (assoc.releaseDeadline.Sub(now) / (2 * time.Second)) * (2 * time.Second)
		if period < 2*time.Second {
			return nil, nil
		}
	}
	if assoc.releaseDeadline.IsZero() {
		assoc.releaseDeadline = now.Add(period)
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
	assoc.releaseRequestSent = true
	return &admittedRequest{wire, request.MessageType(), peer, socket, trace}, nil
}

func (conn *PfcpConnection) serviceReleasesLocked(now time.Time) []admittedRequest {
	var outgoing []admittedRequest
	for _, assoc := range conn.NodeAssociations {
		if !assoc.cleanupDeadline.IsZero() {
			if !now.Before(assoc.cleanupDeadline) {
				conn.cleanupFailedLocked(assoc)
				continue
			}
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
	if assoc.cleanupDeadline.IsZero() {
		assoc.cleanupDeadline = now.Add(AssociationCleanupTimeout)
		assoc.cleanupNext = now
	}
	if !now.Before(assoc.cleanupDeadline) {
		conn.cleanupFailedLocked(assoc)
		return
	}
	if !now.Before(assoc.cleanupNext) {
		conn.cleanupAssociationLocked(assoc, now)
	}
}
func (conn *PfcpConnection) cleanupAssociationLocked(assoc *NodeAssociation, now time.Time) {
	if conn.terminalError != nil {
		return
	}
	assoc.cleanupAttempts++
	for id, session := range assoc.Sessions {
		if err := conn.DeleteSession(session); err != nil {
			assoc.cleanupError = err
			log.Error().Err(err).Str("node", assoc.ID).Uint64("session", id).Uint32("attempt", assoc.cleanupAttempts).Msg("Rule cleanup failed; retain session ownership and IDs")
		} else {
			delete(assoc.Sessions, id)
			delete(assoc.sessionEntities, id)
		}
		if time.Now().After(assoc.cleanupDeadline) && len(assoc.Sessions) > 0 {
			conn.cleanupFailedLocked(assoc)
			return
		}
	}
	if len(assoc.Sessions) == 0 {
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
		return
	}
	delay := 100 * time.Millisecond
	for n := uint32(1); n < assoc.cleanupAttempts && delay < 500*time.Millisecond; n++ {
		delay = min(500*time.Millisecond, delay*2)
	}
	// Journal work can take time; start backoff after the failed attempt.
	retryBase := time.Now()
	if now.After(retryBase) {
		retryBase = now
	}
	assoc.cleanupNext = retryBase.Add(delay)
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
	conn.DeleteAllAssociations()
	for conn.GetAssiciationCount() != 0 && conn.FatalError() == nil {
		time.Sleep(25 * time.Millisecond)
		conn.stateMu.Lock()
		conn.serviceReleasesLocked(time.Now())
		conn.stateMu.Unlock()
	}
}
