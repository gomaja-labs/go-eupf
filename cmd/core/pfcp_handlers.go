// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

type PfcpFunc func(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error)

type PfcpHandlerMap map[uint8]PfcpFunc

func (handlerMap PfcpHandlerMap) Handle(conn *PfcpConnection, buf []byte, addr *net.UDPAddr) error {
	log.Debug().Msgf("Handling PFCP message from %s", addr)
	// TS 29.244 V20.1.0 clauses 6.5, 7.2.1A, 8.2.25 and 8.2.58:
	// both functions must advertise BUNDL before any bundled message is handled.
	// Reject the entire unsupported/oversized bundle before decoding or replying.
	if len(buf) > 0 && buf[0]>>5 == 1 && buf[0]&0x04 != 0 {
		conn.stateMu.RLock()
		assoc := conn.GetAssociation(addr.IP.String())
		negotiated := assoc != nil && (&ie.IE{Type: ie.CPFunctionFeatures, Payload: assoc.CPFeatures}).HasBUNDL() && (&ie.IE{Type: ie.UPFunctionFeatures, Payload: conn.featuresOctets}).HasBUNDL()
		conn.stateMu.RUnlock()
		if !negotiated || !boundedBundle(buf) {
			return nil
		}
	}

	incoming, parseErr := message.ParseDatagram(buf)
	var results []error
	if parseErr != nil {
		log.Warn().Err(parseErr).Str("peer", addr.String()).Msg("Invalid PFCP datagram")
		results = append(results, parseErr)
		for _, failure := range datagramFailures(parseErr) {
			if h := failure.Header; h != nil {
				conn.failResponse(h.Type, h.Sequence(), addr, failure.Err)
			}
			var version *message.UnsupportedVersionError
			var decode *ie.DecodeError
			switch {
			case errors.As(failure.Err, &version):
				// TS 29.244 V20.1.0 clauses 7.6.2 and 7.4.4.7.
				if err := conn.SendMessage(message.NewVersionNotSupportedResponse(version.Header.Sequence()), addr); err != nil {
					results = append(results, err)
				}
			case failure.Header != nil && errors.As(failure.Err, &decode) && failure.Header.Type != message.MsgTypeHeartbeatRequest:
				// TS 29.244 V20.1.0 clause 7.6.7: malformed IE framing requires Cause 68.
				var offending *ie.IE
				if !decode.TypeUnknown {
					offending = ie.NewOffendingIE(decode.Type)
				}
				conn.stateMu.RLock()
				response := conn.errorResponse(failure.Header.Type+1, conn.peerSessionSEID(failure.Header.SEID, addr.IP.String()), failure.Header.Sequence(), ie.CauseInvalidLength, offending)
				conn.stateMu.RUnlock()
				if response != nil {
					if err := conn.SendMessage(response, addr); err != nil {
						results = append(results, err)
					}
				}
			}
		}
	}
	for _, incomingMsg := range incoming {
		invalidFrame := false
		for _, failure := range datagramFailures(parseErr) {
			if failure.Header != nil && failure.Header.Type == incomingMsg.MessageType() && failure.Header.Sequence() == incomingMsg.Sequence() && failure.Header.SEID == incomingMsg.SEID() {
				invalidFrame = true
				break
			}
		}
		if invalidFrame {
			continue
		}
		if err := handlerMap.handleMessage(conn, incomingMsg, buf, addr); err != nil {
			results = append(results, err)
		}
	}
	return errors.Join(results...)
}

func datagramFailures(err error) []*message.DatagramError {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var failures []*message.DatagramError
		for _, child := range joined.Unwrap() {
			failures = append(failures, datagramFailures(child)...)
		}
		return failures
	}
	var failure *message.DatagramError
	if errors.As(err, &failure) {
		return []*message.DatagramError{failure}
	}
	return nil
}

func (handlerMap PfcpHandlerMap) handleMessage(conn *PfcpConnection, incomingMsg message.Message, buf []byte, addr *net.UDPAddr) error {
	// TS 29.244 V20.1.0 clauses 6.4 and 7.6.5: discard unmatched responses.
	var completed *pendingRequest
	if !incomingMsg.IsRequest() {
		completed = conn.takeResponse(incomingMsg.MessageType(), incomingMsg.Sequence(), addr)
		if completed == nil {
			return nil
		}
	}

	handler, ok := handlerMap[incomingMsg.MessageType()]
	if !ok {
		return nil
	} // Clause 7.6.4: discard unknown types before creating labels.
	PfcpMessageRx.WithLabelValues(incomingMsg.MessageTypeName()).Inc()
	// Canonical standalone framing makes a bundled retransmission independent of
	// its siblings; retained IE ordering/content still distinguishes requests.
	requestWire := make([]byte, incomingMsg.MarshalLen())
	if err := incomingMsg.MarshalTo(requestWire); err != nil {
		return err
	}
	key := requestKey{peer: addr.String(), sequence: incomingMsg.Sequence(), typ: incomingMsg.MessageType()}
	digest := sha256.Sum256(requestWire)
	startTime := time.Now()
	conn.stateMu.Lock()
	if conn.isClosed() {
		conn.stateMu.Unlock()
		return net.ErrClosed
	}
	if completed != nil {
		current := conn.GetAssociation(completed.associationID())
		if (completed.association != nil || completed.typ == message.MsgTypeHeartbeatRequest) && current != completed.association {
			conn.stateMu.Unlock()
			return nil
		}
		conn.finishProbeLocked(completed)
	}
	var outgoing message.Message
	var trace bool
	var handlerErr error
	if !incomingMsg.IsRequest() {
		handlerErr = validateIncomingResponse(incomingMsg)
	}

	if incomingMsg.IsRequest() {
		if failure := validateIncomingRequest(incomingMsg); failure != nil {
			handlerErr = failure
			outgoing = conn.errorResponse(incomingMsg.MessageType()+1, conn.responseSEID(incomingMsg, addr.IP.String()), incomingMsg.Sequence(), failure.cause, ie.NewOffendingIE(failure.offending))
		}
	}

	if handlerErr == nil && incomingMsg.IsRequest() {
		switch incomingMsg.MessageType() {
		case message.MsgTypeSessionEstablishmentRequest, message.MsgTypeSessionModificationRequest, message.MsgTypeSessionDeletionRequest:
			if conn.associationForMessage(incomingMsg, addr.IP.String()) == nil {
				handlerErr = errNoEstablishedAssociation
				outgoing = conn.errorResponse(incomingMsg.MessageType()+1, conn.responseSEID(incomingMsg, addr.IP.String()), incomingMsg.Sequence(), ie.CauseNoEstablishedPFCPAssociation, nil)
			}
		}
	}
	assoc := conn.associationForMessage(incomingMsg, addr.IP.String())
	entity := conn.incomingEntity(incomingMsg, addr.IP.String())
	// Heartbeat responses are deterministic from the immutable local timestamp.
	// They must remain answerable even when the bounded response cache is full
	// (clause 6.2.2.2), and unknown peers must not consume cache entries.
	cacheable := incomingMsg.IsRequest() && incomingMsg.MessageType() != message.MsgTypeHeartbeatRequest && handlerErr == nil && assoc != nil
	if cacheable {
		wire, found, err := conn.cachedReply(key, digest)
		if found {
			conn.stateMu.Unlock()
			if err != nil {
				return err
			}

			if wire == nil {
				return nil
			}
			return conn.sendEncoded(wire, incomingMsg.MessageType()+1, addr, false)
		}
	}
	if handlerErr == nil {
		outgoing, trace, handlerErr = handler(conn, incomingMsg, addr.IP.String())
		if handlerErr == nil {
			conn.rememberSessionEntity(incomingMsg, outgoing, addr.IP.String())
		}
	}
	if _, deleted := incomingMsg.(*message.SessionDeletionRequest); deleted {
		if assoc := conn.GetAssociation(addr.IP.String()); assoc != nil {
			conn.pruneEntityMetadata(assoc)
		}
	}
	var wire []byte
	if outgoing != nil {
		wire = make([]byte, outgoing.MarshalLen())
		if err := outgoing.MarshalTo(wire); err != nil {
			handlerErr = errors.Join(handlerErr, err)
			fallback := conn.errorResponse(outgoing.MessageType(), outgoing.SEID(), outgoing.Sequence(), ie.CauseSystemFailure, nil)
			wire = nil
			if fallback != nil {
				wire = make([]byte, fallback.MarshalLen())
				if err := fallback.MarshalTo(wire); err != nil {
					wire = nil
					handlerErr = errors.Join(handlerErr, err)
				}
			}
		}
	}
	if cacheable && conn.associationForMessage(incomingMsg, addr.IP.String()) != nil || incomingMsg.MessageType() == message.MsgTypeAssociationSetupRequest && handlerErr == nil && conn.associationForMessage(incomingMsg, addr.IP.String()) != nil {
		conn.cacheReply(key, digest, wire, entity)
	}
	conn.stateMu.Unlock()
	if trace && IsMessageTraceable(incomingMsg.MessageType()) {
		conn.TraceMessage(buf, addr, true)
	}
	UpfMessageRxLatency.WithLabelValues(incomingMsg.MessageTypeName()).Observe(time.Since(startTime).Seconds())
	if wire != nil {
		handlerErr = errors.Join(handlerErr, conn.sendEncoded(wire, outgoing.MessageType(), addr, trace))
	}
	return handlerErr
}

func setBit(n uint8, pos uint) uint8 {
	n |= (1 << pos)
	return n
}

// Association procedures run under the connection state lock in dispatch.
// TS 29.244 V20.1.0 clauses 6.2.6, 6.2.7 and 6.2.8.
func HandlePfcpAssociationUpdateResponse(_ *PfcpConnection, _ message.Message, _ string) (message.Message, bool, error) {
	return nil, false, nil
}
func HandlePfcpAssociationReleaseRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	request := msg.(*message.AssociationReleaseRequest)
	// Clause 6.2.8.3: the UP function always accepts Release, including a retry
	// after the association has already gone. The response identifies this UPF.
	if failure := validateIncomingRequest(request); failure != nil {
		return conn.errorResponse(message.MsgTypeAssociationReleaseResponse, 0, request.Sequence(), failure.cause, ie.NewOffendingIE(failure.offending)), true, failure
	}
	node, _ := request.NodeID.NodeID()
	for peer, assoc := range conn.NodeAssociations {
		if assoc.ID == nodeIDText(node) {
			conn.deleteAssociation(peer)
		}
	}
	return message.NewAssociationReleaseResponse(request.Sequence(), conn.profile.NodeID(conn.nodeId), ie.NewCause(ie.CauseRequestAccepted)), true, nil
}
func HandlePfcpAssociationSetupRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	request := msg.(*message.AssociationSetupRequest)
	if failure := validateIncomingRequest(request); failure != nil {
		return conn.errorResponse(message.MsgTypeAssociationSetupResponse, 0, request.Sequence(), failure.cause, ie.NewOffendingIE(failure.offending)), true, failure
	}
	printAssociationSetupRequest(request)
	node, _ := request.NodeID.NodeID()
	retained, err := conn.replaceAssociation(nodeIDText(node), addr, request.PFCPSessionRetentionInformation, request.CPFunctionFeatures)
	if err != nil {
		if errors.Is(err, errTransactionCapacity) {
			return conn.errorResponse(message.MsgTypeAssociationSetupResponse, 0, request.Sequence(), ie.CauseNoResourcesAvailable, nil), true, err
		}
		failure := invalidRequestIE(ie.PFCPSessionRetentionInformation, err)
		return conn.errorResponse(message.MsgTypeAssociationSetupResponse, 0, request.Sequence(), failure.cause, ie.NewOffendingIE(failure.offending)), true, failure
	}
	ies := []*ie.IE{conn.profile.NodeID(conn.nodeId), ie.NewCause(ie.CauseRequestAccepted), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewUPFunctionFeatures(conn.featuresOctets...)}
	if retained {
		ies = append(ies, ie.NewPFCPASRspFlags(1))
	}
	return message.NewAssociationSetupResponse(request.Sequence(), ies...), true, nil
}
func HandlePfcpAssociationUpdateRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	request := msg.(*message.AssociationUpdateRequest)
	if failure := validateIncomingRequest(request); failure != nil {
		return conn.errorResponse(message.MsgTypeAssociationUpdateResponse, 0, request.Sequence(), failure.cause, ie.NewOffendingIE(failure.offending)), true, failure
	}
	printAssociationUpdateRequest(request)
	node, _ := request.NodeID.NodeID()
	assoc := conn.associationByID(nodeIDText(node))
	cause := ie.CauseRequestAccepted
	if assoc == nil || assoc.ID != nodeIDText(node) {
		cause = ie.CauseNoEstablishedPFCPAssociation
	} else if request.CPFunctionFeatures != nil {
		if features, err := request.CPFunctionFeatures.CPFunctionFeatures(); err == nil {
			assoc.CPFeatures = append([]byte(nil), features...)
		}
	}
	return message.NewAssociationUpdateResponse(request.Sequence(), conn.profile.NodeID(conn.nodeId), ie.NewCause(cause)), true, nil
}
func newIeNodeID(nodeID string) *ie.IE {
	if address, err := netip.ParseAddr(nodeID); err == nil {
		return ie.NewNodeIDAddress(address)
	}
	return ie.NewNodeIDFQDN(nodeID)
}
func nodeIDText(value ie.NodeIDValue) string {
	if value.Address.IsValid() {
		return value.Address.String()
	}
	return value.FQDN
}
func HandlePfcpAssociationSetupResponse(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	response := msg.(*message.AssociationSetupResponse)
	cause, err := response.Cause.Cause()
	if err != nil || cause != ie.CauseRequestAccepted {
		return nil, true, err
	}
	if failure := requireIEs(requiredIE{ie.NodeID, response.NodeID}, requiredIE{ie.RecoveryTimeStamp, response.RecoveryTimeStamp}); failure != nil {
		return nil, true, failure
	}
	node, _ := response.NodeID.NodeID()
	// CP Function Features is conditional only if optional features are supported
	// (Table 7.4.4.2-1); its absence is valid. Setup timestamps are ignored for
	// restart detection: TS 23.527 V20.0.0 clause 4.2.
	_, err = conn.replaceAssociation(nodeIDText(node), addr, nil, response.CPFunctionFeatures)
	return nil, true, err
}

// TS 29.244 V20.1.0 clauses 7.6.1 and 7.6.6: malformed matched
// responses end retransmission and report an error to the application.
func validateIncomingResponse(msg message.Message) error {
	var node, cause, stamp *ie.IE
	switch response := msg.(type) {
	case *message.HeartbeatResponse:
		return requireIEsError(requiredIE{ie.RecoveryTimeStamp, response.RecoveryTimeStamp})
	case *message.AssociationSetupResponse:
		node, cause, stamp = response.NodeID, response.Cause, response.RecoveryTimeStamp
	case *message.AssociationUpdateResponse:
		node, cause = response.NodeID, response.Cause
	case *message.AssociationReleaseResponse:
		node, cause = response.NodeID, response.Cause
	case *message.SessionReportResponse:
		cause = response.Cause
	default:
		return nil
	}
	if err := requireIEsError(requiredIE{ie.Cause, cause}); err != nil {
		return err
	}
	value, err := cause.Cause()
	if err != nil {
		return err
	}
	if value != ie.CauseRequestAccepted {
		return fmt.Errorf("PFCP %s rejected: cause %d", msg.MessageTypeName(), value)
	}
	if msg.MessageType() != message.MsgTypeSessionReportResponse {
		if err := requireIEsError(requiredIE{ie.NodeID, node}); err != nil {
			return err
		}
	}
	if msg.MessageType() == message.MsgTypeAssociationSetupResponse {
		return requireIEsError(requiredIE{ie.RecoveryTimeStamp, stamp})
	}
	return nil
}
func requireIEsError(fields ...requiredIE) error {
	if failure := requireIEs(fields...); failure != nil {
		return failure
	}
	return nil
}

func HandlePfcpVersionNotSupportedResponse(_ *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	return nil, true, fmt.Errorf("PFCP peer %s rejected the protocol version (highest supported %d)", addr, msg.Version())
}

const maxBundleMessages = 16
const maxBundleBytes = 8192

func boundedBundle(buf []byte) bool {
	if len(buf) > maxBundleBytes {
		return false
	}
	for count := 1; len(buf) > 0; count++ {
		if count > maxBundleMessages || len(buf) < 4 {
			return false
		}
		n := int(binary.BigEndian.Uint16(buf[2:4])) + 4
		if n < 16 || n > len(buf) {
			return false
		}
		buf = buf[n:]
	}
	return true
}
