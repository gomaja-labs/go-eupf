// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"maps"
	"math"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

// Remove the completed drain guard in a fresh FAR version. Its anchor and
// reservation remain live until this final publication's producer grace.
func (conn *PfcpConnection) detachBufferGuard(owner *bufferOwner, cycle *bufferCycle) (result error) {
	before := owner.association.Sessions[owner.session.LocalSEID]
	if before == nil || before.buffers == nil || before.buffers.owner != owner || before.buffers.cycles[cycle.farID] != cycle {
		return errors.New("drain guard has no current session")
	}
	if before.buffers.revision == math.MaxUint64 {
		return errors.New("buffering plan revision exhausted")
	}
	after := cloneSession(before)
	state := *before.buffers
	state.cycles = maps.Clone(state.cycles)
	state.revision++
	delete(state.cycles, cycle.farID)
	after.buffers = &state
	far := after.FARs[cycle.farID]
	if far.FarInfo.Action&2 == 0 || far.FarInfo.BufferCookie != cycle.cookie {
		return errors.New("drain guard has changed")
	}
	oldSlot := far.GlobalId
	far.FarInfo.BufferSessionID, far.FarInfo.BufferCookie, far.FarInfo.BufferLane = 0, 0, 0
	start, finish := conn.prepareSessionMutation(after, updateSessionMutation)
	defer func() { result = errors.Join(result, finish(false)) }()
	if err := start(); err != nil {
		return err
	}
	journal, ok := conn.mapOperations.(*sessionMapProxy).ForwardingPlaneController.(bufferJournal)
	if !ok {
		return errors.New("drain guard has no producer grace")
	}
	grace := journal.BufferGrace()
	slot, err := conn.mapOperations.GetNextFAR()
	if err != nil {
		return err
	}
	far.GlobalId = slot
	after.FARs[cycle.farID] = far
	if err := conn.mapOperations.UpdateFar(slot, far.FarInfo); err != nil {
		return err
	}
	if err := conn.mapOperations.DeleteFar(oldSlot); err != nil {
		return err
	}
	if err := conn.rebindSessionRules(after); err != nil {
		return err
	}
	if err := conn.bindSessionReplies(after); err != nil {
		return err
	}
	if err := finish(true); err != nil {
		return err
	}
	owner.association.Sessions[after.LocalSEID] = after
	owner.session = after
	cycle.canceled, cycle.terminal, cycle.grace = true, true, grace
	if after.bar == nil && len(state.cycles) == 0 {
		owner.canceled, owner.terminal, owner.graced, owner.grace = true, true, false, grace
		after.buffers, after.downlink = nil, nil
		delete(conn.downlinkSessions, after.LocalSEID)
	}
	return nil
}

func (buffering *PacketBuffering) retireDrainedCycle(owner *bufferOwner, cycle *bufferCycle) {
	state, err := buffering.plane.BufferControl(ebpf.BufferCommand{SessionID: owner.session.LocalSEID, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 3})
	if err != nil {
		buffering.fail(err)
		return
	}
	if state.Mode != ebpf.BufferForward || state.Preparing != 0 || cycle.received != state.Produced || cycle.completed != state.Produced {
		return
	}
	if err := owner.conn.detachBufferGuard(owner, cycle); err != nil {
		buffering.fail(err)
	}
}
