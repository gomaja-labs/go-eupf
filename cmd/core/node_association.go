// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import "time"

// NodeAssociation and all reachable session state belong to PfcpConnection.stateMu.
// Handlers run under its write lock; external readers use AssociationSnapshots.
// Heartbeat scheduling uses the connection loop, with no per-peer goroutine.
type NodeAssociation struct {
	ID                string
	Addr              string
	Sessions          map[uint64]*Session
	RecoveryTimestamp time.Time
	CPFeatures        []byte
	endpoint          string
	setupSource       string
	UPFeatures        []byte
	lastOutcomes      map[uint8]requestOutcome
	reportFailures    map[uint64]requestOutcome
	sessionEntities   map[uint64]string
	recoveries        map[string]time.Time
	nextHeartbeat     time.Time
	heartbeatInFlight bool
	failedAt          time.Time
}

func NewNodeAssociation(remoteNodeID, addr string) *NodeAssociation {
	return &NodeAssociation{ID: remoteNodeID, Addr: addr, Sessions: make(map[uint64]*Session), sessionEntities: make(map[uint64]string), recoveries: make(map[string]time.Time)}
}

// newLocalSEID runs under stateMu, like the session registry it consults.
// TS 29.244 V20.1.0 clause 5.6.2: a SEID identifies a session at the UPF's
// address, independently of the CP peer that owns the session.
func (conn *PfcpConnection) newLocalSEID() uint64 {
	if conn.ResourceManager != nil {
		for {
			id := conn.ResourceManager.NextSessionID()
			if id == 0 {
				return 0
			}
			occupied := false
			for _, assoc := range conn.NodeAssociations {
				if assoc.Sessions[id] != nil {
					occupied = true
					break
				}
			}
			if !occupied {
				return id
			}
		}
	}
	if conn.nextSessionID == 0 {
		conn.nextSessionID = 1
	}
	for {
		conn.nextSessionID++
		if conn.nextSessionID == 0 {
			continue
		}
		occupied := false
		for _, association := range conn.NodeAssociations {
			if _, ok := association.Sessions[conn.nextSessionID]; ok {
				occupied = true
				break
			}
		}
		if !occupied {
			return conn.nextSessionID
		}
	}
}
