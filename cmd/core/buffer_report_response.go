// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"math"
	"time"

	"github.com/gomaja-labs/go-pfcp/message"
)

type bufferReportUpdate struct {
	request *pendingRequest
	after   *bufferingActionRule
	drop    bool
}

// Parse and stage controls before completing the requesting procedure. Work
// contains immutable values, never IEs borrowed from a receive buffer. The
// completion callback can run under transport.mu and only queues this plan.
// TS 29.244 V20.1.0 clauses 7.5.9.1 and 7.5.9.2.
func (conn *PfcpConnection) validateBufferReportResponseLocked(request *pendingRequest, response *message.SessionReportResponse) error {
	drop := false
	if response.PFCPSRRspFlags != nil && !isNullIE(response.PFCPSRRspFlags) {
		flags, err := response.PFCPSRRspFlags.PFCPSRRspFlags()
		if err != nil {
			return err
		}
		drop = flags&1 != 0
	}
	if response.UpdateBAR == nil && !drop {
		return nil
	}
	if request.association == nil {
		return errors.New("buffer response has no bound association")
	}
	session := request.association.Sessions[request.localSEID]
	if session == nil {
		return nil
	}
	if !conn.reportBufferContextCurrent(request, session) {
		return nil
	}
	candidate := *session
	if err := stageSessionBAR(&candidate, response); err != nil {
		return err
	}
	if drop && session.downlink != nil && session.downlink.generation == math.MaxUint64 {
		return errors.New("buffering generation exhausted")
	}
	if len(conn.bufferUpdates) >= conn.originatedRequestLimit() {
		return errTransactionCapacity
	}
	request.bufferUpdate = &bufferReportUpdate{request: request, after: candidate.bar, drop: drop}
	return nil
}
func (conn *PfcpConnection) reportBufferContextCurrent(request *pendingRequest, session *Session) bool {
	if request.reportBAR != session.bar || request.reportBufferState != session.downlink || !conn.reportAddressCurrent(request, session) {
		return false
	}
	if session.buffers != nil && request.reportBufferRevision != session.buffers.revision {
		return false
	}
	return session.downlink == nil || request.reportBufferGeneration == session.downlink.generation
}

// Buffer controls run after transport.mu is released. Re-check the same
// association, session lifetime, BAR revision, buffering generation and CP F-SEID
// so a response can never undo a later Session Modification.
func (conn *PfcpConnection) flushBufferReportUpdates() {
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	pending := conn.bufferUpdates
	conn.bufferUpdates = nil
	for _, work := range pending {
		request := work.request
		assoc := conn.associationByID(request.associationID())
		if assoc != request.association || activeAssociation(assoc) == nil {
			continue
		}
		session := assoc.Sessions[request.localSEID]
		if session == nil || !conn.reportBufferContextCurrent(request, session) {
			continue
		}
		if session.buffers != nil {
			candidate, err := conn.applyPacketBufferReportUpdate(assoc, session, work)
			if err != nil {
				conn.terminalError = err
				conn.packetBuffers.fail(err)
				continue
			}
			session = candidate
		}
		if session.bar != work.after {
			session.bar = work.after
			if work.after != nil {
				session.barRevision = work.after.revision
			}
		}
		if work.drop && session.downlink != nil {
			state := session.downlink
			conn.advanceDownlinkGenerationLocked(state)
			clear(state.fars)
			clear(state.pending)
			state.pending = state.pending[:0]
		}
		conn.applyDownlinkDurationLocked(session, time.Now())
	}
}

func (conn *PfcpConnection) applyPacketBufferReportUpdate(assoc *NodeAssociation, before *Session, work *bufferReportUpdate) (_ *Session, result error) {
	candidate := cloneSession(before)
	candidate.bar = work.after
	if work.after != nil {
		candidate.barRevision = work.after.revision
	}
	start, finish := conn.prepareSessionMutation(candidate, updateSessionMutation)
	defer func() { result = errors.Join(result, finish(false)) }()
	conn.stagePacketBuffering(assoc, before, candidate, updateSessionMutation, work.drop)
	if err := start(); err != nil {
		return nil, err
	}
	if err := finish(true); err != nil {
		return nil, err
	}
	assoc.Sessions[candidate.LocalSEID] = candidate
	return candidate, nil
}
