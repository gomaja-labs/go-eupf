// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

type bufferJournal interface {
	JournalBufferControl(ebpf.BufferCommand) error
	BufferGrace() <-chan struct{}
}

type packetBufferPlan struct {
	association                *NodeAssociation
	before, after              *Session
	kind                       sessionMutationKind
	drop                       bool
	owner                      *bufferOwner
	created                    bool
	fresh, cancel, drain, hold []*bufferCycle
	grace                      <-chan struct{}
	started, finished          bool
	activated                  time.Time
	notify                     map[uint32]bool
}

// Stage only private model values. The common session transaction calls begin
// after obtaining the rule journal, before publishing any FAR or PDR.
func (conn *PfcpConnection) stagePacketBuffering(association *NodeAssociation, before, after *Session, kind sessionMutationKind, drop bool, notifyFARs ...uint32) {
	needed := after.buffers != nil || after.bar != nil
	for _, far := range after.FARs {
		needed = needed || far.FarInfo.Action&4 != 0
	}
	if !needed {
		return
	}
	notify := make(map[uint32]bool)
	for _, id := range notifyFARs {
		notify[id] = true
	}
	for id, far := range after.FARs {
		if far.FarInfo.Action&12 == 12 && (before == nil || before.FARs[id].FarInfo.Action&12 != 12) {
			notify[id] = true
		}
	}
	after.bufferPlan = &packetBufferPlan{association: association, before: before, after: after, kind: kind, drop: drop, notify: notify}
}

func (plan *packetBufferPlan) begin(conn *PfcpConnection, tx ebpf.RuleTransaction) error {
	journal, ok := tx.(bufferJournal)
	if !ok {
		return errors.New("rule journal does not support packet buffering")
	}
	plan.grace = journal.BufferGrace()
	plan.started = true
	plan.activated = time.Now()
	after := plan.after
	if after.bar != nil && after.bar.durationPresent && after.bar.duration == 0 {
		bar := *after.bar
		bar.durationPresent, bar.dlPacketCountPresent = false, false
		bar.dlPacketCount = 0
		after.bar = &bar
	}
	if after.buffers == nil {
		owner, err := conn.reservePacketBuffers(plan.association, after)
		if err != nil {
			return err
		}
		plan.owner, plan.created = owner, true
		for _, cycle := range after.buffers.cycles {
			if cycle != nil {
				plan.fresh = append(plan.fresh, cycle)
			}
		}
		return plan.applyLimits(conn, journal)
	}
	owner := after.buffers.owner
	plan.owner = owner
	if owner.released && plan.kind == deleteSessionMutation {
		after.buffers = nil
		plan.owner = nil
		return nil
	}
	if owner.canceled || owner.released {
		return errors.New("buffering lifetime is retiring")
	}
	if after.buffers.revision == math.MaxUint64 {
		return errors.New("buffering plan revision exhausted")
	}
	state := &packetBufferSession{owner: owner, cycles: make(map[uint32]*bufferCycle), revision: after.buffers.revision + 1}
	after.buffers = state
	for id, far := range after.FARs {
		far.FarInfo.BufferSessionID, far.FarInfo.BufferCookie, far.FarInfo.BufferLane = 0, 0, 0
		after.FARs[id] = far
	}
	barRemoved := plan.before != nil && plan.before.bar != nil && after.bar == nil
	for farID, cycle := range plan.before.buffers.cycles {
		far, exists := after.FARs[farID]
		canceled := plan.drop || plan.kind == deleteSessionMutation || !exists || far.FarInfo.Action&6 == 0
		if barRemoved && plan.before.FARs[farID].BARID != nil {
			canceled = true
		}
		if canceled {
			plan.cancel = append(plan.cancel, cycle)
			if err := journal.JournalBufferControl(ebpf.BufferCommand{SessionID: after.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferDiscard}); err != nil {
				return err
			}
			continue
		}
		state.cycles[farID] = cycle
		far.FarInfo.BufferSessionID, far.FarInfo.BufferCookie, far.FarInfo.BufferLane = after.LocalSEID, cycle.cookie, cycle.lane
		after.FARs[farID] = far
		if far.FarInfo.Action&4 != 0 {
			// Every BUFF|NOCP instruction starts a notification period, even
			// while the preceding drain still owns this lane (clause 5.2.3.1).
			if plan.notify[farID] {
				if err := journal.JournalBufferControl(ebpf.BufferCommand{SessionID: after.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 10}); err != nil {
					return err
				}
			}
			plan.hold = append(plan.hold, cycle)
			if cycle.draining {
				if err := journal.JournalBufferControl(ebpf.BufferCommand{SessionID: after.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferHold}); err != nil {
					return err
				}
			}
		} else if !cycle.draining {
			plan.drain = append(plan.drain, cycle)
			if err := journal.JournalBufferControl(ebpf.BufferCommand{SessionID: after.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferDrain}); err != nil {
				return err
			}
		}
	}
	if plan.kind != deleteSessionMutation {
		for farID, far := range after.FARs {
			if far.FarInfo.Action&4 == 0 || state.cycles[farID] != nil {
				continue
			}
			cycle, err := conn.packetBuffers.reserveCycle(owner, farID)
			if err != nil {
				return err
			}
			plan.fresh = append(plan.fresh, cycle)
			state.cycles[farID] = cycle
			far.FarInfo.BufferSessionID, far.FarInfo.BufferCookie, far.FarInfo.BufferLane = after.LocalSEID, cycle.cookie, cycle.lane
			after.FARs[farID] = far
		}
	}
	return plan.applyLimits(conn, journal)
}

func (plan *packetBufferPlan) applyLimits(conn *PfcpConnection, journal bufferJournal) error {
	if plan.kind == deleteSessionMutation {
		return nil
	}
	buffering := conn.packetBuffers
	limit := buffering.options.PerSession
	barLimit, dlLimit := limit, limit
	until := uint64(0)
	if bar := plan.after.bar; bar != nil {
		if bar.packetCountPresent {
			barLimit = min(barLimit, uint32(bar.packetCount))
		}
		if bar.dlPacketCountPresent {
			dlLimit = min(dlLimit, uint32(bar.dlPacketCount))
		}
		if bar.durationPresent && bar.duration > 0 && bar.duration != time.Duration(math.MaxInt64) {
			deadline := plan.activated.Add(bar.duration)
			if state := plan.after.downlink; state != nil && state.durationRevision == bar.durationRevision && !state.extendedUntil.IsZero() {
				deadline = state.extendedUntil
			}
			delta := deadline.Sub(buffering.baseTime)
			if delta < 0 {
				until = buffering.baseNS
			} else {
				until = buffering.baseNS + uint64(delta)
			}
		}
	}
	var first *bufferCycle
	for id, cycle := range plan.after.buffers.cycles {
		if first == nil {
			first = cycle
		}
		far := plan.after.FARs[id]
		uses := far.FarInfo.Action&4 != 0 && downlinkBARAssociated(plan.after, far)
		if err := journal.JournalBufferControl(ebpf.BufferCommand{SessionID: plan.after.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 7, UsesBAR: uses}); err != nil {
			return err
		}
	}
	if first == nil {
		return nil
	}
	return journal.JournalBufferControl(ebpf.BufferCommand{SessionID: plan.after.LocalSEID, Cookie: first.cookie, Lane: first.lane, Operation: 2, Limit: limit, BARLimit: barLimit, BARDLLimit: dlLimit, BARUntilNS: until})
}

// Controls such as DROBU can replace a cookie without an Update FAR IE. Publish
// those derived references in a fresh FAR version and rebind its PDR readers in
// the same journal. Explicit FAR operations have already reserved fresh slots.
func (plan *packetBufferPlan) publish(conn *PfcpConnection, tx ebpf.RuleTransaction) error {
	if plan.kind == deleteSessionMutation || plan.before == nil {
		return nil
	}
	changed := false
	for id, far := range plan.after.FARs {
		previous, exists := plan.before.FARs[id]
		if !exists || previous.GlobalId != far.GlobalId || previous.FarInfo == far.FarInfo {
			continue
		}
		slot, err := tx.GetNextFAR()
		if err != nil {
			return err
		}
		if err := tx.UpdateFar(slot, far.FarInfo); err != nil {
			return err
		}
		if err := tx.DeleteFar(previous.GlobalId); err != nil {
			return err
		}
		far.GlobalId = slot
		plan.after.FARs[id] = far
		changed = true
	}
	if changed {
		if err := conn.rebindSessionRules(plan.after); err != nil {
			return err
		}
		return conn.bindSessionReplies(plan.after)
	}
	return nil
}

func (buffering *PacketBuffering) reserveCycle(owner *bufferOwner, farID uint32) (*bufferCycle, error) {
	if err := buffering.prepareOutput(owner.session.LocalSEID); err != nil {
		return nil, err
	}
	if owner.nextCookie == math.MaxUint64 {
		return nil, errors.New("buffer cookie exhausted")
	}
	for lane := uint32(0); uint64(lane) <= uint64(len(owner.cycles)); lane++ {
		if owner.cycles[lane] != nil {
			continue
		}
		owner.nextCookie++
		cycle := &bufferCycle{farID: farID, lane: lane, cookie: owner.nextCookie, head: noBufferedPacket}
		if _, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 5, Mode: ebpf.BufferHold}); err != nil {
			return nil, fmt.Errorf("reserve buffering lane: %w", err)
		}
		owner.cycles[lane] = cycle
		return cycle, nil
	}
	return nil, ebpf.ErrRuleCapacity
}

func (plan *packetBufferPlan) finish(conn *PfcpConnection, committed, terminal bool) {
	if plan.finished || !plan.started || plan.owner == nil {
		return
	}
	plan.finished = true
	owner := plan.owner
	if committed {
		owner.session = plan.after
		if state := plan.after.downlink; state != nil {
			for id := range plan.notify {
				flow, exists := state.fars[id]
				if exists {
					if !conn.resetDownlinkFAR(&flow) {
						state.stopped = true
					}
					state.fars[id] = flow
				}
			}
			kept := state.pending[:0]
			for _, notice := range state.pending {
				if !plan.notify[notice.farID] {
					kept = append(kept, notice)
				}
			}
			clear(state.pending[len(kept):])
			state.pending = kept
			for id := range state.fars {
				far, exists := plan.after.FARs[id]
				if !exists || far.FarInfo.Action&12 != 12 {
					delete(state.fars, id)
				}
			}
		}
		for _, cycle := range plan.cancel {
			cycle.canceled, cycle.terminal, cycle.grace = true, terminal, plan.grace
		}
		for _, cycle := range plan.drain {
			cycle.draining, cycle.grace, cycle.ready = true, plan.grace, false
			cycle.drainStarted = plan.activated
			cycle.drainReady = time.Time{}
			if plan.before != nil && plan.before.downlink != nil {
				state := plan.before.downlink
				cycle.bufferedBAR = downlinkBARAssociated(plan.before, plan.before.FARs[cycle.farID])
				cycle.bufferedUntil, cycle.bufferedCutoff, cycle.bufferedInfinite = state.extendedUntil, state.suppressBefore, state.infinite
			}
		}
		for _, cycle := range plan.hold {
			cycle.draining, cycle.ready = false, false
			cycle.drainStarted = time.Time{}
			cycle.drainReady = time.Time{}
		}
		if plan.kind == deleteSessionMutation || plan.after.bar == nil && len(plan.after.buffers.cycles) == 0 {
			owner.canceled, owner.terminal, owner.grace = true, terminal, plan.grace
			delete(conn.downlinkSessions, owner.session.LocalSEID)
			if state := owner.session.downlink; state != nil {
				state.stopped = true
				clear(state.pending)
				state.pending = state.pending[:0]
			}
			if plan.kind != deleteSessionMutation {
				plan.after.buffers, plan.after.downlink = nil, nil
			}
		} else {
			owner.active = true
			if plan.before != nil && hasBufferedBAR(plan.before) && !hasBufferedBAR(plan.after) && plan.after.downlink != nil && plan.after.bar != nil && (plan.after.bar.durationPresent || plan.after.bar.dlPacketCountPresent) {
				conn.endDownlinkDurationLocked(plan.after, plan.activated)
			}
			conn.applyDownlinkDurationLocked(plan.after, plan.activated)
		}
	} else {
		for _, cycle := range plan.fresh {
			_, err := conn.packetBuffers.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 1, Mode: ebpf.BufferDiscard})
			cycle.canceled, cycle.terminal, cycle.grace = true, terminal && err == nil, plan.grace
			if err != nil {
				conn.packetBuffers.fail(err)
			}
		}
		if plan.created {
			owner.canceled, owner.terminal, owner.grace = true, terminal, plan.grace
		}
	}
	if !committed || len(plan.cancel) > 0 || len(plan.drain) > 0 || plan.kind == deleteSessionMutation {
		conn.packetBuffers.schedule(owner)
	}
	conn.packetBuffers.signal()
}

func bufferGraceDone(grace <-chan struct{}) bool {
	if grace == nil {
		return false
	}
	select {
	case <-grace:
		return true
	default:
		return false
	}
}

func hasBufferedBAR(session *Session) bool {
	for _, far := range session.FARs {
		if far.FarInfo.Action&4 != 0 && downlinkBARAssociated(session, far) {
			return true
		}
	}
	return false
}
