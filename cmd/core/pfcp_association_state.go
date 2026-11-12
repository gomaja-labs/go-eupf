// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// replaceAssociation is called under stateMu. An association is identified by
// Node ID, even when Setup arrives from a different PFCP entity/IP address.
// TS 29.244 V20.1.0 clause 6.2.6.2.2 and Table 7.4.4.1-2.
func (conn *PfcpConnection) replaceAssociation(id, addr string, retention, features *ie.IE) (bool, error) {
	// The current session index admits one Node ID per peer IP. Reject an
	// occupied-address conflict; it must never tear down a different node's
	// sessions. Supporting several nodes behind one NAT IP needs a port-aware
	// session index as well as endpoint-aware reliable delivery.
	if existing := conn.GetAssociation(addr); existing != nil && existing.ID != id {
		return false, errTransactionCapacity
	}
	var retainedEntities []string
	if retention != nil {
		fields, err := retention.PFCPSessionRetentionInformation()
		if err != nil {
			return false, fmt.Errorf("session retention: %w", err)
		}
		for _, entity := range fields.CPPFCPEntityIPAddress {
			fields, err := entity.CPPFCPEntityIPAddress()
			if err != nil {
				continue // Clause 7.6.8: ignore a semantically invalid optional child.
			}
			if fields.IPv4Address != nil {
				retainedEntities = append(retainedEntities, fields.IPv4Address.String())
			}
			if fields.IPv6Address != nil {
				retainedEntities = append(retainedEntities, fields.IPv6Address.String())
			}
		}
	}
	fresh := NewNodeAssociation(id, addr)
	if value, err := features.CPFunctionFeatures(); err == nil {
		fresh.CPFeatures = append([]byte(nil), value...)
	}
	fresh.endpoint = net.JoinHostPort(addr, "8805")
	fresh.nextHeartbeat = time.Now().Add(conn.heartbeatInterval())
	replaces := false
	for peer, old := range conn.NodeAssociations {
		if old.ID == id || peer == addr {
			replaces = true
		}
	}
	limit := conn.maxAssociations
	if limit == 0 {
		limit = 1024
	}
	if !replaces && uint32(len(conn.NodeAssociations)) >= limit {
		return false, errTransactionCapacity
	}
	retained := false
	for peer, old := range conn.NodeAssociations {
		if old.ID != id && peer != addr {
			continue
		}
		for seid, session := range old.Sessions {
			entity := old.sessionEntities[seid]
			if entity == "" {
				entity = old.Addr
			}
			keep := retention != nil && old.ID == id && len(retainedEntities) == 0
			for _, candidate := range retainedEntities {
				if candidate == entity && old.ID == id {
					keep = true
				}
			}
			if keep {
				fresh.Sessions[seid] = session
				if stamp := old.recoveries[entity]; !stamp.IsZero() {
					fresh.recoveries[entity] = stamp
				}
				if entity == addr {
					fresh.RecoveryTimestamp = old.RecoveryTimestamp
				}
				fresh.sessionEntities[seid] = entity
				if seid > fresh.NextSessionID {
					fresh.NextSessionID = seid
				}
				retained = true
			} else {
				conn.DeleteSession(session)
				conn.ReleaseResources(session.LocalSEID)
			}
		}
		delete(conn.NodeAssociations, peer)
		conn.forgetPeerExceptSetup(peer)
	}
	conn.NodeAssociations[addr] = fresh
	// PSREI confirms that the requested retention operation succeeded, including
	// a request for an empty set of existing sessions.
	return retained || (replaces && retention != nil), nil
}

// observeRecovery compares only heartbeat timestamps; Setup timestamps are
// explicitly ignored. A smaller value is a reordered stale message, not another
// restart. TS 23.007 V19.2.0 clause 19A; TS 23.527 V20.0.0 clauses 4.2 and 4.4.2.
func (conn *PfcpConnection) observeRecovery(addr string, stamp time.Time) bool {
	return conn.observeEntityRecovery(addr, addr, stamp)
}
func (conn *PfcpConnection) observeEntityRecovery(addr, entity string, stamp time.Time) bool {
	assoc := conn.GetAssociation(addr)
	if assoc == nil {
		return true
	}
	known := entity == addr
	for _, candidate := range assoc.sessionEntities {
		if candidate == entity {
			known = true
			break
		}
	}
	if !known {
		return true
	} // Unknown entities receive replies without allocating state.
	if assoc.recoveries == nil {
		assoc.recoveries = make(map[string]time.Time)
	}
	previous := assoc.recoveries[entity]
	if entity == addr && !assoc.RecoveryTimestamp.IsZero() {
		previous = assoc.RecoveryTimestamp
	}
	if stamp.Before(previous) {
		return false
	}
	if !previous.IsZero() && stamp.After(previous) {
		for seid, session := range assoc.Sessions {
			origin := assoc.sessionEntities[seid]
			if origin == "" {
				origin = addr
			}
			if origin != entity {
				continue
			}
			conn.DeleteSession(session)
			conn.ReleaseResources(session.LocalSEID)
			delete(assoc.Sessions, seid)
			delete(assoc.sessionEntities, seid)
		}
		conn.forgetEntityTransactions(addr, entity)
	}
	conn.pruneEntityMetadata(assoc)
	assoc.recoveries[entity] = stamp
	if entity == addr {
		assoc.RecoveryTimestamp = stamp
	}
	assoc.failedAt = time.Time{}
	return true
}

func (conn *PfcpConnection) heartbeatInterval() time.Duration {
	if conn.heartbeatEvery <= 0 {
		return 5 * time.Second
	}
	return conn.heartbeatEvery
}
func (conn *PfcpConnection) serviceHeartbeats(now time.Time) {
	conn.stateMu.Lock()
	var peers []string
	for addr, assoc := range conn.NodeAssociations {
		if !assoc.failedAt.IsZero() && now.Sub(assoc.failedAt) >= conn.heartbeatGrace {
			PfcpAssociationPrunes.Inc()
			conn.deleteAssociation(addr)
			continue
		}
		if conn.heartbeatTimeout <= 0 || assoc.heartbeatInFlight || now.Before(assoc.nextHeartbeat) {
			continue
		}
		assoc.heartbeatInFlight = true
		assoc.nextHeartbeat = now.Add(conn.heartbeatInterval())
		peers = append(peers, addr)
	}
	conn.stateMu.Unlock()
	for _, peer := range peers {
		if err := SendHeartbeatRequest(conn, 0, peer); err != nil {
			conn.stateMu.Lock()
			if assoc := conn.GetAssociation(peer); assoc != nil {
				assoc.heartbeatInFlight = false
			}
			conn.stateMu.Unlock()
		}
	}
}
func (conn *PfcpConnection) heartbeatFailed(addr string, expected ...*NodeAssociation) {
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if assoc := conn.GetAssociation(addr); assoc != nil {
		if conn.heartbeatTimeout <= 0 && len(expected) > 0 {
			return
		}
		if len(expected) > 0 && assoc != expected[0] {
			return
		}
		assoc.heartbeatInFlight = false
		if assoc.failedAt.IsZero() {
			assoc.failedAt = time.Now()
		}
		if conn.heartbeatGrace <= 0 {
			PfcpAssociationPrunes.Inc()
			conn.deleteAssociation(addr)
		}
	}
}
func (conn *PfcpConnection) forgetPeer(addr string) { conn.forgetPeerTransactions(addr, false, "") }
func (conn *PfcpConnection) forgetPeerExceptSetup(addr string) {
	conn.forgetPeerTransactions(addr, true, "")
}
func (conn *PfcpConnection) forgetPeerTransactions(addr string, keepSetup bool, entity string) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	for seq, request := range state.pending {
		if request.peer.IP.String() == addr && (entity == "" || request.entity == entity) {
			state.deletePending(seq)
		}
	}
	for key, entry := range state.responses {
		host, _, _ := net.SplitHostPort(key.peer)
		if host == addr && (!keepSetup || key.typ != message.MsgTypeAssociationSetupRequest) && (entity == "" || entry.entity == entity) {
			state.bytes -= len(entry.wire)
			delete(state.responses, key)
		}
	}
}

func (conn *PfcpConnection) peerAddress(addr string) string {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	if assoc := conn.GetAssociation(addr); assoc != nil && assoc.endpoint != "" {
		return assoc.endpoint
	}
	return net.JoinHostPort(addr, "8805")
}

// AssociationSnapshots returns independent values, including session rule maps
// and IP byte slices, so JSON encoding never walks live state after unlocking.
func (conn *PfcpConnection) AssociationSnapshots() map[string]*NodeAssociation {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	result := make(map[string]*NodeAssociation, len(conn.NodeAssociations))
	for addr, assoc := range conn.NodeAssociations {
		copy := *assoc
		copy.CPFeatures = append([]byte(nil), assoc.CPFeatures...)
		copy.sessionEntities = nil
		copy.recoveries = nil
		copy.Sessions = make(map[uint64]*Session, len(assoc.Sessions))
		for seid, session := range assoc.Sessions {
			copy.Sessions[seid] = cloneSession(session)
		}
		result[addr] = &copy
	}
	return result
}
func cloneSession(session *Session) *Session {
	copy := *session
	copy.PDRs = maps.Clone(session.PDRs)
	copy.FARs = maps.Clone(session.FARs)
	copy.QERs = maps.Clone(session.QERs)
	copy.URRs = maps.Clone(session.URRs)
	for id, pdr := range copy.PDRs {
		pdr.Ipv4 = append(net.IP(nil), pdr.Ipv4...)
		pdr.Ipv6 = append(net.IP(nil), pdr.Ipv6...)
		pdr.PdrInfo.SdfFilter = slices.Clone(pdr.PdrInfo.SdfFilter)
		for i, f := range pdr.PdrInfo.SdfFilter {
			pdr.PdrInfo.SdfFilter[i] = cloneSdfFilter(f)
		}
		if pdr.PCCInfo != nil {
			pcc := *pdr.PCCInfo
			pcc.SDFFilter = cloneSdfFilter(pcc.SDFFilter)
			pdr.PCCInfo = &pcc
		}
		copy.PDRs[id] = pdr
	}
	return &copy
}

func (conn *PfcpConnection) rememberEndpoint(msg message.Message, peer *net.UDPAddr) {
	if msg.MessageType() != message.MsgTypeAssociationSetupRequest && msg.MessageType() != message.MsgTypeAssociationSetupResponse {
		return
	}
	if assoc := conn.GetAssociation(peer.IP.String()); assoc != nil {
		assoc.endpoint = peer.String()
	}
}

type queuedMessage struct {
	msg      message.Message
	endpoint string
	trace    bool
}

func (conn *PfcpConnection) sendQueued(messages []queuedMessage) {
	for _, out := range messages {
		peer, err := net.ResolveUDPAddr("udp", out.endpoint)
		if err == nil {
			_ = conn.SendMessageWithTrace(out.msg, peer, out.trace)
		}
	}
}
func (conn *PfcpConnection) hasOutstanding(typ uint8, ip string) bool {
	conn.transport.mu.Lock()
	defer conn.transport.mu.Unlock()
	for _, req := range conn.transport.pending {
		if req.typ == typ && req.peer.IP.String() == ip {
			return true
		}
	}
	return false
}
func (conn *PfcpConnection) localNodeID() string {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	return conn.nodeId
}
func cloneSdfFilter(filter ebpf.SdfFilter) ebpf.SdfFilter {
	filter.SrcAddress.Ip = append(net.IP(nil), filter.SrcAddress.Ip...)
	filter.SrcAddress.Mask = append(net.IPMask(nil), filter.SrcAddress.Mask...)
	filter.DstAddress.Ip = append(net.IP(nil), filter.DstAddress.Ip...)
	filter.DstAddress.Mask = append(net.IPMask(nil), filter.DstAddress.Mask...)
	return filter
}

// A session belongs to the CP PFCP entity in its CP F-SEID, not necessarily the
// source IP of a NATed datagram. TS 29.244 Table 7.4.4.1-2; TS 23.007 clause 19A.
func sessionEntity(request *message.SessionEstablishmentRequest, fallback string) string {
	fields, err := request.CPFSEID.FSEID()
	if err != nil {
		return fallback
	}
	if fields.IPv4Address != nil {
		return fields.IPv4Address.String()
	}
	if fields.IPv6Address != nil {
		return fields.IPv6Address.String()
	}
	return fallback
}
func (conn *PfcpConnection) rememberSessionEntity(request, response message.Message, peer string) {
	if deleted, ok := request.(*message.SessionDeletionRequest); ok {
		if assoc := conn.GetAssociation(peer); assoc != nil && assoc.Sessions[deleted.SEID()] == nil {
			delete(assoc.sessionEntities, deleted.SEID())
			conn.pruneEntityMetadata(assoc)
		}
		return
	}
	req, ok := request.(*message.SessionEstablishmentRequest)
	if !ok {
		return
	}
	reply, ok := response.(*message.SessionEstablishmentResponse)
	if !ok {
		return
	}
	cause, err := reply.Cause.Cause()
	if err != nil || cause != ie.CauseRequestAccepted {
		return
	}
	fields, err := reply.UPFSEID.FSEID()
	if err != nil {
		return
	}
	if assoc := conn.GetAssociation(peer); assoc != nil && assoc.Sessions[fields.SEID] != nil {
		assoc.sessionEntities[fields.SEID] = sessionEntity(req, peer)
	}
}

func (conn *PfcpConnection) forgetEntityTransactions(addr, entity string) {
	conn.forgetPeerTransactions(addr, false, entity)
}
func (conn *PfcpConnection) incomingEntity(msg message.Message, peer string) string {
	switch request := msg.(type) {
	case *message.SessionEstablishmentRequest:
		return sessionEntity(request, peer)
	case *message.HeartbeatRequest:
		fields, err := request.SourceIPAddress.SourceIPAddress()
		if err == nil {
			if fields.IPv4Address != nil {
				return fields.IPv4Address.String()
			}
			if fields.IPv6Address != nil {
				return fields.IPv6Address.String()
			}
		}
	}
	if assoc := conn.GetAssociation(peer); assoc != nil {
		if entity := assoc.sessionEntities[msg.SEID()]; entity != "" {
			return entity
		}
	}
	return peer
}
func (conn *PfcpConnection) outgoingContext(msg message.Message, peer string) (string, *NodeAssociation) {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	if assoc := conn.GetAssociation(peer); assoc != nil {
		for seid, session := range assoc.Sessions {
			if msg.SEID() != 0 && session.RemoteSEID == msg.SEID() {
				if entity := assoc.sessionEntities[seid]; entity != "" {
					return entity, assoc
				}
			}
		}
	}
	return peer, conn.GetAssociation(peer)
}

func (conn *PfcpConnection) pruneEntityMetadata(assoc *NodeAssociation) {
	active := map[string]bool{assoc.Addr: true}
	for seid, entity := range assoc.sessionEntities {
		if assoc.Sessions[seid] == nil {
			delete(assoc.sessionEntities, seid)
		} else {
			active[entity] = true
		}
	}
	for entity := range assoc.recoveries {
		if !active[entity] {
			delete(assoc.recoveries, entity)
		}
	}
}
