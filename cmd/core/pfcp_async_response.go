package core

import (
	"net"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

type usageResponse struct {
	message.Message
	ready    <-chan error
	finalize func()
}

func (conn *PfcpConnection) deferredUsageResponse(msg message.Message, finalize func()) message.Message {
	if conn.responseWait == nil {
		return msg
	}
	result := &usageResponse{Message: msg, ready: conn.responseWait, finalize: finalize}
	conn.responseWait = nil
	return result
}

// Final usage is the only response work that waits for reclamation. State and
// admission have already committed. A duplicate finds the nil cached outcome
// and is dropped while this one response waits (TS 29.244 V20.1.0 clause 6.4).
func (conn *PfcpConnection) completeUsageResponse(response *usageResponse, key requestKey, digest [32]byte, peer *net.UDPAddr, entity string, assoc *NodeAssociation, trace bool, started time.Time) {
	var err error
	select {
	case <-conn.done:
		return
	case err = <-response.ready:
	}
	msg := response.Message
	if err != nil {
		log.Error().Err(err).Uint64("seid", msg.SEID()).Msg("Final usage unavailable after bounded data-plane recovery")
		msg = conn.errorResponse(msg.MessageType(), msg.SEID(), msg.Sequence(), ie.CauseSystemFailure, nil)
	} else {
		response.finalize()
	}
	if msg == nil {
		return
	}
	wire := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(wire); err != nil {
		log.Error().Err(err).Msg("Encode deferred PFCP response")
		return
	}
	conn.stateMu.Lock()
	if conn.isClosed() {
		conn.stateMu.Unlock()
		return
	}
	if assoc != nil && conn.associationByID(assoc.ID) == assoc {
		conn.cacheReply(key, digest, wire, entity, assoc.ID)
	}
	conn.stateMu.Unlock()
	UpfMessageRxLatency.WithLabelValues(message.MessageTypeName(key.typ)).Observe(time.Since(started).Seconds())
	if err := conn.sendEncoded(wire, msg.MessageType(), peer, trace); err != nil {
		log.Warn().Err(err).Msg("Send final PFCP usage response")
	}
}

func (conn *PfcpConnection) ruleFailureChannel() <-chan error {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	if plane, ok := conn.mapOperations.(interface{ RuleFailures() <-chan error }); ok {
		return plane.RuleFailures()
	}
	return nil
}
