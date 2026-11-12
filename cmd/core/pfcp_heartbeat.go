// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package core

import (
	"net"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

func HandlePfcpHeartbeatRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	hbreq := msg.(*message.HeartbeatRequest)
	ts, err := hbreq.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		log.Warn().Msgf("Got Heartbeat Request with invalid TS: %s, from: %s", err, addr)
		return nil, true, err
	} else {
		log.Debug().Msgf("Got Heartbeat Request with TS: %s, from: %s", ts, addr)
	}

	// TS 29.244 V20.1.0 clause 6.2.2.2: answer even unknown peers.
	if !conn.observeEntityRecovery(addr, conn.incomingEntity(msg, addr), ts) {
		return nil, true, nil
	}

	hbres := message.NewHeartbeatResponse(hbreq.SequenceNumber, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))
	log.Debug().Msgf("Sent Heartbeat Response to: %s", addr)
	return hbres, true, nil
}

func HandlePfcpHeartbeatResponse(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	hbresp := msg.(*message.HeartbeatResponse)
	ts, err := hbresp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		log.Warn().Msgf("Got Heartbeat Response with invalid TS: %s, from: %s", err, addr)
		return nil, true, err
	}

	log.Debug().Msgf("Got Heartbeat Response with TS: %s, from: %s", ts, addr)

	if association := conn.GetAssociation(addr); association != nil {
		association.heartbeatInFlight = false
		association.nextHeartbeat = time.Now().Add(conn.heartbeatInterval())
	}
	conn.observeRecovery(addr, ts)
	return nil, true, nil
}

func SendHeartbeatRequest(conn *PfcpConnection, sequenceID uint32, associationAddr string) error {
	hbreq := message.NewHeartbeatRequest(sequenceID, append([]*ie.IE{ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp)}, conn.profile.HeartbeatRequestAdditionalIEs()...)...)
	log.Debug().Msgf("Sent Heartbeat Request to: %s", associationAddr)
	udpAddr, err := net.ResolveUDPAddr("udp", conn.peerAddress(associationAddr))
	if err != nil {
		return err
	}
	return conn.SendMessageWithTrace(hbreq, udpAddr, true)
}
