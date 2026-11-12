// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"time"

	"github.com/gomaja-labs/go-pfcp/message"
)

// SetHeartbeatTimeout changes the timeout policy without exposing a timer owned
// by another goroutine. Zero disables probing and cancels outstanding probes.
func (conn *PfcpConnection) SetHeartbeatTimeout(seconds uint32) {
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	conn.transport.mu.Lock()
	defer conn.transport.mu.Unlock()
	conn.heartbeatTimeout = time.Duration(seconds) * time.Second
	for _, assoc := range conn.NodeAssociations {
		assoc.heartbeatInFlight = false
		assoc.failedAt = time.Time{}
	}
	for seq, req := range conn.transport.pending {
		if req.typ == message.MsgTypeHeartbeatRequest {
			conn.completeRequestLocked(req, requestResult{outcome: requestCanceled, err: errors.New("heartbeat timeout changed")})
			conn.transport.deletePending(seq)
		}
	}
}

// SetAssociationSetupTimeout resets the connection's one setup ticker. A zero
// interval is rejected by retaining the existing interval.
func (conn *PfcpConnection) SetAssociationSetupTimeout(seconds uint32) {
	if seconds == 0 {
		return
	}
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if conn.AssociationSetupTicker == nil {
		conn.AssociationSetupTicker = time.NewTicker(time.Duration(seconds) * time.Second)
	} else {
		conn.AssociationSetupTicker.Reset(time.Duration(seconds) * time.Second)
	}
}
func (conn *PfcpConnection) associationTicker() *time.Ticker {
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if conn.AssociationSetupTicker == nil {
		conn.AssociationSetupTicker = time.NewTicker(conn.setupInterval())
	}
	return conn.AssociationSetupTicker
}

func (conn *PfcpConnection) setupInterval() time.Duration {
	if conn.setupEvery <= 0 {
		return 5 * time.Second
	}
	return conn.setupEvery
}
