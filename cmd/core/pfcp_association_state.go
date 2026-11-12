// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/rs/zerolog/log"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// replaceAssociation is called under stateMu. An association is identified by
// Node ID, even when Setup arrives from a different PFCP entity/IP address.
// TS 29.244 V20.1.0 clause 6.2.6.2.2 and Table 7.4.4.1-2.
func (conn *PfcpConnection) replaceAssociation(id, addr string, retention, features *ie.IE) (bool, error) {
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
	destination := addr
	if ip := net.ParseIP(id); ip != nil {
		destination = ip.String()
	}
	fresh := NewNodeAssociation(id, destination)
	fresh.setupSource = addr
	fresh.UPFeatures = append([]byte(nil), conn.featuresOctets...)
	if value, err := features.CPFunctionFeatures(); err == nil {
		fresh.CPFeatures = append([]byte(nil), value...)
	}
	fresh.endpoint = net.JoinHostPort(destination, "8805")
	fresh.nextHeartbeat = time.Now().Add(conn.heartbeatInterval())
	replaces := false
	for _, old := range conn.NodeAssociations {
		if old.ID == id {
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
	for _, old := range conn.NodeAssociations {
		if old.ID != id {
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
				retained = true
			} else {
				if err := conn.DeleteSession(session); err != nil {
					return false, fmt.Errorf("replace association session %d: %w", seid, err)
				}
				conn.forgetSession(old, seid)
			}
		}
	}
	for peer, old := range conn.NodeAssociations {
		if old.ID == id {
			conn.indexAssociation(old, -1)
			delete(conn.NodeAssociations, peer)
			conn.forgetPeerExceptSetup(old.ID)
		}
	}
	conn.NodeAssociations[id] = fresh
	conn.indexAssociation(fresh, 1)
	// PSREI confirms that the requested retention operation succeeded, including
	// a request for an empty set of existing sessions.
	return retained || (replaces && retention != nil), nil
}

// observeRecovery compares only heartbeat timestamps; Setup timestamps are
// explicitly ignored. A smaller value is a reordered stale message, not another
// restart. TS 23.007 V19.2.0 clause 19A; TS 23.527 V20.0.0 clauses 4.2 and 4.4.2.
func (conn *PfcpConnection) observeRecovery(addr string, stamp time.Time) bool {
	if assoc := conn.GetAssociation(addr); assoc != nil {
		return conn.observeEntityRecovery(assoc.ID, assoc.Addr, stamp)
	}
	return true
}
func (conn *PfcpConnection) observeEntityRecovery(addr, entity string, stamp time.Time, establishing ...bool) bool {
	assoc := conn.GetAssociation(addr)
	if assoc == nil || !assoc.cleanupDeadline.IsZero() {
		return true
	}
	_, remembered := assoc.recoveries[entity]
	known := remembered || entity == assoc.Addr || entity == assoc.setupSource || len(establishing) > 0 && establishing[0]
	known = known || conn.addressIndex[entity][assoc] > 0
	if !known {
		return true
	} // Unknown entities receive replies without allocating state.
	if assoc.recoveries == nil {
		assoc.recoveries = make(map[string]time.Time)
	}
	previous := assoc.recoveries[entity]
	if entity == assoc.Addr && !assoc.RecoveryTimestamp.IsZero() {
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
			if err := conn.DeleteSession(session); err != nil {
				log.Error().Err(err).Uint64("session", seid).Msg("Retain restart context after failed cleanup")
				if assoc.failedAt.IsZero() {
					assoc.failedAt = time.Now()
				}
				return false
			}
			conn.forgetSession(assoc, seid)
		}
		conn.forgetEntityTransactions(addr, entity)
	}
	assoc.recoveries[entity] = stamp
	if entity == assoc.Addr {
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
	conn.serviceReportCleanupLocked(now)
	outgoing := conn.serviceReleasesLocked(now)
	var peers []string
	for addr, assoc := range conn.NodeAssociations {
		if !assoc.releaseDeadline.IsZero() || !assoc.cleanupDeadline.IsZero() {
			continue
		}
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
	_ = conn.sendAdmitted(outgoing)
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
		if !assoc.releaseDeadline.IsZero() || !assoc.cleanupDeadline.IsZero() {
			return
		}
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
func (conn *PfcpConnection) forgetPeerTransactions(id string, keepSetup bool, entity string) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	for seq, request := range state.pending {
		if request.associationID() == id && (entity == "" || request.entity == entity) {
			conn.completeRequestLocked(request, requestResult{outcome: requestCanceled, err: errors.New("PFCP association context invalidated")})
			state.deletePending(seq)
		}
	}
	if budget := state.responseBudgets[id]; budget != nil {
		for element := budget.entries.Front(); element != nil; {
			next := element.Next()
			e := element.Value.(*responseIndex)
			entry := state.responses[e.key]
			if (!keepSetup || e.key.typ != message.MsgTypeAssociationSetupRequest) && (entity == "" || entry.entity == entity) {
				state.removeResponse(e)
			}
			element = next
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
		copy.UPFeatures = append([]byte(nil), assoc.UPFeatures...)
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
	copy.CPFSEIDIPv4 = slices.Clone(session.CPFSEIDIPv4)
	copy.CPFSEIDIPv6 = slices.Clone(session.CPFSEIDIPv6)
	copy.PDRs = maps.Clone(session.PDRs)
	copy.FARs = maps.Clone(session.FARs)
	copy.QERs = maps.Clone(session.QERs)
	copy.URRs = maps.Clone(session.URRs)
	for id, pdr := range copy.PDRs {
		pdr.LocalFTEIDIPv4 = cloneIP(pdr.LocalFTEIDIPv4)
		pdr.Ipv4 = append(net.IP(nil), pdr.Ipv4...)
		pdr.Ipv6 = append(net.IP(nil), pdr.Ipv6...)
		if pdr.FARID != nil {
			value := *pdr.FARID
			pdr.FARID = &value
		}
		pdr.QERIDs = slices.Clone(pdr.QERIDs)
		pdr.URRIDs = slices.Clone(pdr.URRIDs)
		pdr.PdrInfo.ReturnQerIDs = slices.Clone(pdr.PdrInfo.ReturnQerIDs)
		pdr.PdrInfo.QerIDs = slices.Clone(pdr.PdrInfo.QerIDs)
		pdr.PdrInfo.UrrIDs = slices.Clone(pdr.PdrInfo.UrrIDs)
		pdr.PdrInfo.QFIs = slices.Clone(pdr.PdrInfo.QFIs)
		pdr.PdrInfo.UEIPv4 = append(net.IP(nil), pdr.PdrInfo.UEIPv4...)
		pdr.PdrInfo.UEIPv6 = append(net.IP(nil), pdr.PdrInfo.UEIPv6...)
		pdr.PdrInfo.UEIPv6Mask = append(net.IPMask(nil), pdr.PdrInfo.UEIPv6Mask...)
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

type queuedMessage struct {
	msg         message.Message
	association string
	trace       bool
	localSEID   uint64
}

func (conn *PfcpConnection) sendQueued(messages []queuedMessage) {
	for _, out := range messages {
		if err := conn.sendAssociationRequest(out.msg, out.association, out.trace, out.localSEID); err != nil {
			log.Warn().Err(err).Msg("Admit session report")
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
	assoc := conn.associationForMessage(request, peer)
	if assoc == nil {
		return
	}
	if deleted, ok := request.(*message.SessionDeletionRequest); ok {
		if assoc.Sessions[deleted.SEID()] == nil {
			delete(assoc.sessionEntities, deleted.SEID())
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
	if err == nil && assoc.Sessions[fields.SEID] != nil {
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
	if assoc := conn.associationForMessage(msg, peer); assoc != nil {
		if entity := assoc.sessionEntities[msg.SEID()]; entity != "" {
			return entity
		}
	}
	return peer
}

// associationForMessage resolves protocol identity before looking at the source.
// TS 29.244 V20.1.0 clause 5.8.1: F-SEID entity addresses may differ from Node ID.
// The source allow-list is enforced once, before decoding, and applies equally
// to Setup, additional CP addresses, responses and heartbeats.
func (conn *PfcpConnection) associationForMessage(msg message.Message, peer string) *NodeAssociation {
	var node *ie.IE
	switch m := msg.(type) {
	case *message.SessionEstablishmentRequest:
		node = m.NodeID
	case *message.AssociationSetupRequest:
		node = m.NodeID
	case *message.AssociationSetupResponse:
		node = m.NodeID
	case *message.AssociationUpdateRequest:
		node = m.NodeID
	case *message.AssociationReleaseRequest:
		node = m.NodeID
	default:
		if msg.SEID() != 0 {
			if assoc := conn.sessionAssociation(msg.SEID()); assoc != nil {
				return activeAssociation(assoc)
			}
		}
		return activeAssociation(conn.GetAssociation(peer))
	}
	value, err := node.NodeID()
	if err != nil {
		return nil
	}
	return activeAssociation(conn.associationByID(nodeIDText(value)))
}

func (conn *PfcpConnection) associationByID(id string) *NodeAssociation {
	if assoc := conn.NodeAssociations[id]; assoc != nil {
		return assoc
	}
	for _, assoc := range conn.NodeAssociations {
		if assoc.ID == id {
			return assoc
		}
	}
	return nil
}

func (conn *PfcpConnection) sessionAssociation(seid uint64) *NodeAssociation {
	for _, assoc := range conn.NodeAssociations {
		if assoc.Sessions[seid] != nil {
			return assoc
		}
	}
	return nil
}

// controlIP chooses an advertised CP F-SEID family usable by the local socket.
// Both addresses remain stored; TS 29.244 V20.1.0 clause 4.3.2.
func (s *Session) controlIP(conn *PfcpConnection) net.IP {
	if conn.nodeAddrV4.Addr().Is6() && s.CPFSEIDIPv6 != nil {
		return s.CPFSEIDIPv6
	}
	if s.CPFSEIDIPv4 != nil {
		return s.CPFSEIDIPv4
	}
	return s.CPFSEIDIPv6
}

// responseSEID also resolves requests from a different admitted CP address.
// TS 29.244 V20.1.0 clause 7.2.2.4.2: unknown session context uses zero.
func (conn *PfcpConnection) responseSEID(request message.Message, peer string) uint64 {
	if assoc := conn.associationForMessage(request, peer); assoc != nil {
		return conn.peerSEID(request, assoc.ID)
	}
	return conn.peerSEID(request, "")
}

func activeAssociation(assoc *NodeAssociation) *NodeAssociation {
	if assoc != nil && !assoc.cleanupDeadline.IsZero() {
		return nil
	}
	return assoc
}

// Admission keeps the explicit Node ID/session context through reliable delivery;
// several associations can share an IP, so the destination cannot recover it.
// TS 29.244 V20.1.0 clauses 4.2.2, 4.3.2 and 5.8.1.
func (conn *PfcpConnection) sendAssociationRequest(msg message.Message, id string, trace bool, localSEID uint64) error {
	conn.stateMu.Lock()
	assoc := activeAssociation(conn.GetAssociation(id))
	if assoc == nil {
		conn.stateMu.Unlock()
		return errNoEstablishedAssociation
	}
	endpoint := assoc.endpoint
	if endpoint == "" {
		endpoint = net.JoinHostPort(assoc.Addr, "8805")
	}
	entity := assoc.Addr
	if localSEID != 0 {
		// TS 29.244 V20.1.0 clauses 5.6.2, 5.22.2 and 4.3.2:
		// CP SEID values can collide between entities of the same SMF set.
		session := assoc.Sessions[localSEID]
		if session == nil || len(session.controlIP(conn)) == 0 {
			conn.stateMu.Unlock()
			return ErrSessionNotFound
		}
		report, ok := msg.(*message.SessionReportRequest)
		if !ok {
			conn.stateMu.Unlock()
			return fmt.Errorf("unsupported session originator %T", msg)
		}
		report.Header.SEID = session.RemoteSEID
		endpoint = net.JoinHostPort(session.controlIP(conn).String(), "8805")
		entity = assoc.sessionEntities[localSEID]
	}
	peer, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		conn.stateMu.Unlock()
		return err
	}
	socket := conn.socket()
	wire, err := conn.prepareRequestContext(msg, peer, trace, socket, entity, assoc, localSEID)
	if err == nil {
		conn.bindReportUsageLocked(msg, assoc, localSEID)
	}
	if err == nil && msg.MessageType() == message.MsgTypeHeartbeatRequest {
		assoc.heartbeatInFlight = true
	}
	conn.stateMu.Unlock()
	if err != nil {
		return err
	}
	return conn.sendEncodedAtSocket(wire, msg.MessageType(), peer, trace, socket)
}
