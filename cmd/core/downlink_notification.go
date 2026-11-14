// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"math"
	"net"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type downlinkFARState struct {
	cookie uint64
	epoch  uint64
	bar    bool
	flows  uint64
	absent bool
}
type downlinkNotice struct {
	epoch      uint64
	bar        bool
	farID      uint32
	cookie     uint64
	pdrID      uint16
	qfi        uint8
	qfiPresent bool
	arrived    time.Time
}
type downlinkNotifications struct {
	generation       uint64
	stopped          bool
	fars             map[uint32]downlinkFARState
	pending          []downlinkNotice
	durationRevision uint64
	extendedUntil    time.Time
	infinite         bool
	suppressBefore   time.Time
}
type reportedDownlink struct{ notice downlinkNotice }

// Notice storage is reserved before a session is published. It never grows in
// response to packet input. Session state and callbacks are owned by stateMu.
func newDownlinkNotifications(capacity int) *downlinkNotifications {
	return &downlinkNotifications{generation: 1, fars: make(map[uint32]downlinkFARState), pending: make([]downlinkNotice, 0, capacity)}
}
func (state downlinkFARState) contains(qfi uint8, present bool) bool {
	if !present {
		return state.absent
	}
	return state.flows&(uint64(1)<<qfi) != 0
}
func (state *downlinkFARState) set(qfi uint8, present, value bool) {
	if !present {
		state.absent = value
		return
	}
	if value {
		state.flows |= uint64(1) << qfi
	} else {
		state.flows &^= uint64(1) << qfi
	}
}

// TS 29.244 V20.1.0 clause 5.2.3.1: EPC coalesces per FAR and 5GC
// per QoS flow/FAR. A present QFI zero is distinct from an unavailable QFI.
// The ordered buffer consumer supplies the first admitted packet of each flow.
func (conn *PfcpConnection) noteDownlinkPacketLocked(session *Session, farID uint32, record ebpf.BufferRecord, arrived time.Time) {
	state := session.downlink
	far, exists := session.FARs[farID]
	if state == nil || state.stopped || !exists || record.SessionID != session.LocalSEID || record.Cookie == 0 || record.Cookie != far.FarInfo.BufferCookie || far.FarInfo.Action&12 != 12 || !record.Notify || record.PDRID > math.MaxUint16 || record.QFI > 63 {
		return
	}
	conn.applyDownlinkDurationLocked(session, arrived)
	associated := downlinkBARAssociated(session, far)
	if associated && (state.infinite || !state.extendedUntil.IsZero() && arrived.Before(state.extendedUntil) || !state.suppressBefore.IsZero() && arrived.Before(state.suppressBefore)) {
		return
	}
	qfi, present := record.QFI, session.Is5G && record.QFIPresent
	flow := state.fars[farID]
	if flow.cookie != record.Cookie {
		flow = downlinkFARState{cookie: record.Cookie, epoch: 1, bar: associated}
	} else if flow.bar != associated {
		if !conn.resetDownlinkFAR(&flow) {
			return
		}
		flow.bar = associated
	}
	if flow.contains(qfi, present) {
		return
	}
	flow.set(qfi, present, true)
	state.fars[farID] = flow
	if len(state.pending) == cap(state.pending) {
		capacity := min(max(1, 2*cap(state.pending)), 65*len(session.FARs))
		pending := make([]downlinkNotice, len(state.pending), capacity)
		copy(pending, state.pending)
		state.pending = pending
	}
	state.pending = append(state.pending, downlinkNotice{farID: farID, cookie: record.Cookie, pdrID: uint16(record.PDRID), qfi: qfi, qfiPresent: present, arrived: arrived, epoch: flow.epoch, bar: associated})
	conn.watchDownlinkSession(session)
}

func downlinkBARAssociated(session *Session, far SFarInfo) bool {
	return session.bar != nil && far.BARID != nil && *far.BARID == session.bar.id
}
func (conn *PfcpConnection) resetDownlinkFAR(flow *downlinkFARState) bool {
	if flow.epoch == math.MaxUint64 {
		conn.terminalError = errors.New("downlink FAR notification epoch exhausted")
		return false
	}
	flow.epoch++
	flow.flows, flow.absent = 0, false
	return true
}
func (conn *PfcpConnection) resetBARNotifications(session *Session) {
	state := session.downlink
	if session.buffers != nil {
		for id, cycle := range session.buffers.cycles {
			if downlinkBARAssociated(session, session.FARs[id]) {
				conn.resetKernelNotice(session, id, cycle.cookie, 10, 0)
			}
		}
	}
	for id, flow := range state.fars {
		if flow.bar {
			conn.resetKernelNotice(session, id, flow.cookie, 10, 0)
			if !conn.resetDownlinkFAR(&flow) {
				state.stopped = true
			}
			state.fars[id] = flow
		}
	}
	conn.clearBARPending(state)
}
func (conn *PfcpConnection) clearBARPending(state *downlinkNotifications) {
	kept := state.pending[:0]
	for _, notice := range state.pending {
		if !notice.bar {
			kept = append(kept, notice)
		}
	}
	clear(state.pending[len(kept):])
	state.pending = kept
}
func markSuppressionEnd(state *downlinkNotifications, now time.Time) {
	until := now
	if !state.extendedUntil.IsZero() && state.extendedUntil.Before(until) {
		until = state.extendedUntil
	}
	if state.suppressBefore.Before(until) {
		state.suppressBefore = until
	}
}

// TS 29.244 V20.1.0 clause 5.2.4.2: extended buffering suppresses
// further notifications unless EDBNC is supported, which is not advertised.
func (conn *PfcpConnection) applyDownlinkDurationLocked(session *Session, now time.Time) {
	state := session.downlink
	if state == nil {
		return
	}
	defer conn.watchDownlinkSession(session)
	if session.bar == nil {
		if state.durationRevision != 0 || state.infinite || !state.extendedUntil.IsZero() {
			markSuppressionEnd(state, now)
			conn.resetBARNotifications(session)
			state.durationRevision = 0
			state.extendedUntil = time.Time{}
			state.infinite = false
		}
		return
	}
	if state.durationRevision != session.bar.durationRevision {
		wasActive := state.infinite || !state.extendedUntil.IsZero()
		if wasActive {
			markSuppressionEnd(state, now)
		}
		state.durationRevision = session.bar.durationRevision
		state.extendedUntil = time.Time{}
		state.infinite = false
		if session.bar.durationPresent && session.bar.duration > 0 {
			state.infinite = session.bar.duration == time.Duration(math.MaxInt64)
			if !state.infinite {
				state.extendedUntil = now.Add(session.bar.duration)
			}
			conn.clearBARPending(state)
		} else if wasActive || session.bar.durationPresent {
			conn.endDownlinkDurationLocked(session, now)
		}
	}
	if !state.extendedUntil.IsZero() && !now.Before(state.extendedUntil) {
		conn.endDownlinkDurationLocked(session, now)
	}
}

// Stop applying and remove the extended-only parameters when buffering ends;
// a later first eligible packet may notify again (clause 5.2.4.2).
func (conn *PfcpConnection) endDownlinkDurationLocked(session *Session, now time.Time) {
	state := session.downlink
	markSuppressionEnd(state, now)
	conn.resetBARNotifications(session)
	state.extendedUntil = time.Time{}
	state.infinite = false
	if session.bar == nil {
		state.durationRevision = 0
		return
	}
	if !session.bar.durationPresent && !session.bar.dlPacketCountPresent {
		state.durationRevision = session.bar.durationRevision
		return
	}
	bar := *session.bar
	bar.duration, bar.durationPresent = 0, false
	bar.dlPacketCount, bar.dlPacketCountPresent = 0, false
	if err := storeBAR(session, &bar, true); err != nil {
		conn.terminalError = err
	}
	state.durationRevision = session.bar.durationRevision
}

// One endpoint service loop admits reports; network writes happen after stateMu
// is released. Retransmission and every terminal result belong to the existing
// originated-request machinery (TS 29.244 V20.1.0 clauses 6.4, 7.5.8).
func (conn *PfcpConnection) serviceDownlinkNotifications(now time.Time) {
	conn.stateMu.Lock()
	var outgoing []admittedRequest
	conn.transport.mu.Lock()
	available := min(128, max(0, conn.originatedRequestLimit()-len(conn.transport.pending)))
	conn.transport.mu.Unlock()
	for id, assoc := range conn.downlinkSessions {
		session := assoc.Sessions[id]
		if activeAssociation(conn.associationByID(assoc.ID)) != assoc || session == nil || session.downlink == nil || conn.isClosed() {
			delete(conn.downlinkSessions, id)
			continue
		}
		conn.applyDownlinkDurationLocked(session, now)
		state := session.downlink
		if available == 0 {
			continue
		}
		pending := state.pending
		state.pending = state.pending[:0]
		for _, notice := range pending {
			if available == 0 {
				state.pending = append(state.pending, notice)
				continue
			}
			far, ok := session.FARs[notice.farID]
			if !ok || far.FarInfo.BufferCookie != notice.cookie || far.FarInfo.Action&12 != 12 || state.fars[notice.farID].epoch != notice.epoch {
				continue
			}
			delay := time.Duration(0)
			if !session.Is5G && downlinkBARAssociated(session, far) {
				delay = session.bar.notificationDelay
			}
			if now.Before(notice.arrived.Add(delay)) {
				state.pending = append(state.pending, notice)
				continue
			}
			children := []*ie.IE{ie.NewPDRID(notice.pdrID)}
			if notice.qfiPresent {
				children = append(children, ie.NewDownlinkDataServiceInformation(false, true, 0, notice.qfi))
			}
			report := message.NewSessionReportRequest(session.RemoteSEID, 0, ie.NewReportType(0, 0, 0, 1), ie.NewDownlinkDataReport(children...))
			peer := &net.UDPAddr{IP: cloneIP(session.controlIP(conn)), Port: 8805}
			socket := conn.socket()
			wire, err := conn.prepareRequestContext(report, peer, session.Traced, socket, assoc.sessionEntities[id], assoc, id)
			if err != nil {
				state.pending = append(state.pending, notice)
				continue
			}
			bound := &reportedDownlink{notice: notice}
			conn.transport.mu.Lock()
			conn.transport.pending[report.Sequence()].downlink = bound
			conn.transport.mu.Unlock()
			outgoing = append(outgoing, admittedRequest{wire: wire, typ: report.MessageType(), peer: peer, socket: socket, trace: session.Traced})
			available--
		}
		clear(state.pending[len(state.pending):cap(state.pending)])
		conn.watchDownlinkSession(session)
		if available == 0 {
			break
		}
	}
	conn.stateMu.Unlock()
	_ = conn.sendAdmitted(outgoing)
}

// Failed terminal outcomes re-arm only a subsequent eligible packet. They do
// not start an unbounded sequence of new requesting procedures without input.
func (conn *PfcpConnection) downlinkNotificationCurrent(request *pendingRequest, session *Session) bool {
	bound := request.downlink
	state := request.reportBufferState
	if bound == nil || state == nil || session.downlink != state || state.generation != request.reportBufferGeneration {
		return false
	}
	flow, ok := state.fars[bound.notice.farID]
	far, exists := session.FARs[bound.notice.farID]
	return ok && exists && flow.cookie == bound.notice.cookie && flow.epoch == bound.notice.epoch && far.FarInfo.BufferCookie == bound.notice.cookie && far.FarInfo.Action&12 == 12
}

func (conn *PfcpConnection) completeDownlinkNotificationLocked(request *pendingRequest, session *Session, result requestResult) bool {
	if !conn.downlinkNotificationCurrent(request, session) {
		return false
	}
	bound := request.downlink
	state := session.downlink
	if !conn.reportAddressCurrent(request, session) {
		conn.reportRetries = append(conn.reportRetries, request)
		return true
	}
	if result.outcome != requestAccepted {
		flow := state.fars[bound.notice.farID]
		if conn.packetBuffers != nil {
			index := uint64(65)
			if session.Is5G {
				index = 64
			}
			if bound.notice.qfiPresent {
				index = uint64(bound.notice.qfi)
			}
			conn.resetKernelNotice(session, bound.notice.farID, bound.notice.cookie, 9, index)
		}
		flow.set(bound.notice.qfi, bound.notice.qfiPresent, false)
		state.fars[bound.notice.farID] = flow
	}
	return false
}

func (conn *PfcpConnection) advanceDownlinkGenerationLocked(state *downlinkNotifications) {
	if state.generation == math.MaxUint64 {
		state.stopped = true
		conn.terminalError = errors.New("buffer notification generation exhausted")
		return
	}
	state.generation++
}

func (conn *PfcpConnection) resetKernelNotice(session *Session, farID uint32, cookie uint64, operation uint32, sequence uint64) {
	if conn.packetBuffers == nil || session.buffers == nil {
		return
	}
	for _, cycle := range session.buffers.owner.cycles {
		if cycle == nil || cycle.farID != farID || cycle.cookie != cookie || cycle.canceled {
			continue
		}
		if _, err := conn.packetBuffers.plane.BufferControl(ebpf.BufferCommand{SessionID: session.LocalSEID, Cookie: cookie, Lane: cycle.lane, Operation: operation, Sequence: sequence}); err != nil {
			conn.packetBuffers.fail(err)
		}
		return
	}
}

// Only sessions with pending reports or a finite duration need maintenance.
// Ordinary idle BUFF sessions do not add a scan to every PFCP datagram.
func (conn *PfcpConnection) watchDownlinkSession(session *Session) {
	state := session.downlink
	if state == nil || state.stopped || len(state.pending) == 0 && state.extendedUntil.IsZero() {
		delete(conn.downlinkSessions, session.LocalSEID)
		return
	}
	var assoc *NodeAssociation
	if session.buffers != nil {
		assoc = session.buffers.owner.association
	}
	if assoc == nil {
		assoc = conn.downlinkSessions[session.LocalSEID]
	}
	if assoc == nil {
		for _, candidate := range conn.NodeAssociations {
			if candidate.Sessions[session.LocalSEID] == session {
				assoc = candidate
				break
			}
		}
	}
	if assoc != nil {
		if conn.downlinkSessions == nil {
			conn.downlinkSessions = make(map[uint64]*NodeAssociation)
		}
		conn.downlinkSessions[session.LocalSEID] = assoc
	}
}
