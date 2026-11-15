// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/rs/zerolog/log"

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
	if reason := conn.reportBufferContextMismatch(request, session); reason != "" {
		logDiscardedBufferControl(request, reason)
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

// Internal rule generations and drain retirement do not represent a new CP
// instruction. TS 29.244 V20.1.0 clauses 7.5.9.1/.2 and 8.2.32.
func (conn *PfcpConnection) reportBufferContextMismatch(request *pendingRequest, session *Session) string {
	if session == nil {
		return "session removed"
	}
	if request.reportBufferState != session.downlink {
		return "notification lifetime replaced"
	}
	if !conn.reportAddressCurrent(request, session) {
		return "CP F-SEID changed"
	}
	if request.reportBufferRevision != session.bufferControlRevision {
		return "CP buffering instruction changed"
	}
	return ""
}

func logDiscardedBufferControl(request *pendingRequest, reason string) {
	log.Debug().Uint64("seid", request.localSEID).Str("reason", reason).Msg("Discard stale Report Response buffering controls")
}

// Compare CP rule content, excluding fresh map slots and usage-only changes.
// A repeated BUFF|NOCP instruction still begins a new period (clause 5.2.3.1).
func bufferingModificationChanged(before, after *Session, drop bool, notify []uint32) bool {
	if drop || len(notify) > 0 || before.bar != after.bar {
		return true
	}
	relevant := make(map[uint32]bool)
	for _, session := range []*Session{before, after} {
		for id, far := range session.FARs {
			if far.FarInfo.Action&4 != 0 || session.buffers != nil && session.buffers.cycles[id] != nil {
				relevant[id] = true
			}
		}
	}
	for id := range relevant {
		old, oldExists := before.FARs[id]
		next, nextExists := after.FARs[id]
		old.GlobalId, next.GlobalId = 0, 0
		old.FarInfo.BufferSessionID, old.FarInfo.BufferCookie, old.FarInfo.BufferLane = 0, 0, 0
		next.FarInfo.BufferSessionID, next.FarInfo.BufferCookie, next.FarInfo.BufferLane = 0, 0, 0
		if oldExists != nextExists || !reflect.DeepEqual(old, next) {
			return true
		}
	}
	ids := make(map[uint32]bool)
	for _, session := range []*Session{before, after} {
		for id, pdr := range session.PDRs {
			if pdr.FARID != nil && relevant[*pdr.FARID] {
				ids[id] = true
			}
		}
	}
	for id := range ids {
		old, oldExists := before.PDRs[id]
		next, nextExists := after.PDRs[id]
		if !old.LocalFTEIDIPv4.Equal(next.LocalFTEIDIPv4) {
			return true
		}
		for _, pdr := range []*SPDRInfo{&old, &next} {
			pdr.LocalFTEIDIPv4 = nil
			pdr.URRIDs = nil
			pdr.PdrInfo.UrrIDs = nil
			pdr.PdrInfo.FarId = 0
			pdr.PdrInfo.QerIDs = nil
			pdr.PdrInfo.ReturnFarID = 0
			pdr.PdrInfo.ReturnQerIDs = nil
			pdr.PdrInfo.TraceFlag = false
		}
		if oldExists != nextExists || !reflect.DeepEqual(old, next) {
			return true
		}
		for _, qid := range next.QERIDs {
			oldQ, oldExists := before.QERs[qid]
			nextQ, nextExists := after.QERs[qid]
			oldQ.GlobalId, nextQ.GlobalId = 0, 0
			oldQ.QerInfo.PolicerID, nextQ.QerInfo.PolicerID = 0, 0
			if oldExists != nextExists || oldQ != nextQ {
				return true
			}
		}
	}
	return false
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
			logDiscardedBufferControl(request, "association replaced or removed")
			continue
		}
		session := assoc.Sessions[request.localSEID]
		if reason := conn.reportBufferContextMismatch(request, session); reason != "" {
			logDiscardedBufferControl(request, reason)
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
