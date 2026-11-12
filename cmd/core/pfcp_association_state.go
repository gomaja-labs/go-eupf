// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"fmt"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"maps"
	"net"
	"slices"
	"time"

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
				return false, fmt.Errorf("retention entity: %w", err)
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
	assoc := conn.GetAssociation(addr)
	if assoc == nil {
		return true
	}
	if stamp.Before(assoc.RecoveryTimestamp) {
		return false
	}
	if !assoc.RecoveryTimestamp.IsZero() && stamp.After(assoc.RecoveryTimestamp) {
		for seid, session := range assoc.Sessions {
			entity := assoc.sessionEntities[seid]
			if entity != "" && entity != addr {
				continue
			}
			conn.DeleteSession(session)
			conn.ReleaseResources(session.LocalSEID)
			delete(assoc.Sessions, seid)
			delete(assoc.sessionEntities, seid)
		}
		conn.forgetPeer(addr)
	}
	assoc.RecoveryTimestamp = stamp
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
		SendHeartbeatRequest(conn, 0, peer)
	}
}
func (conn *PfcpConnection) heartbeatFailed(addr string) {
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if assoc := conn.GetAssociation(addr); assoc != nil {
		assoc.heartbeatInFlight = false
		if assoc.failedAt.IsZero() {
			assoc.failedAt = time.Now()
		}
		if conn.heartbeatGrace <= 0 {
			conn.deleteAssociation(addr)
		}
	}
}
func (conn *PfcpConnection) forgetPeer(addr string) { conn.forgetPeerTransactions(addr, false) }
func (conn *PfcpConnection) forgetPeerExceptSetup(addr string) {
	conn.forgetPeerTransactions(addr, true)
}
func (conn *PfcpConnection) forgetPeerTransactions(addr string, keepSetup bool) {
	state := &conn.transport
	state.mu.Lock()
	defer state.mu.Unlock()
	for seq, request := range state.pending {
		if request.peer.IP.String() == addr {
			delete(state.pending, seq)
		}
	}
	for key, entry := range state.responses {
		host, _, _ := net.SplitHostPort(key.peer)
		if host == addr && (!keepSetup || key.typ != message.MsgTypeAssociationSetupRequest) {
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
