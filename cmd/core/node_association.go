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
	NextSessionID     uint64
	Sessions          map[uint64]*Session
	RecoveryTimestamp time.Time
	CPFeatures        []byte
	endpoint          string
	sessionEntities   map[uint64]string
	recoveries        map[string]time.Time
	nextHeartbeat     time.Time
	heartbeatInFlight bool
	failedAt          time.Time
}

func NewNodeAssociation(remoteNodeID, addr string) *NodeAssociation {
	return &NodeAssociation{ID: remoteNodeID, Addr: addr, NextSessionID: 1, Sessions: make(map[uint64]*Session), sessionEntities: make(map[uint64]string), recoveries: make(map[string]time.Time)}
}
func (association *NodeAssociation) NewLocalSEID() uint64 {
	association.NextSessionID++
	return association.NextSessionID
}
