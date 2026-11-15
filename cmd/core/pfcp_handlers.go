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

func (handlerMap PfcpHandlerMap) Handle(conn *PfcpConnection, buf []byte, addr *net.UDPAddr, local netip.AddrPort) error {
	log.Debug().Msgf("Handling PFCP message from %s", addr)
	bundled := len(buf) > 0 && buf[0]>>5 == 1 && buf[0]&4 != 0

	incoming, parseErr := message.ParseDatagram(buf)
	var results []error
	if parseErr != nil {
		log.Warn().Err(parseErr).Str("peer", addr.String()).Msg("Invalid PFCP datagram")
		results = append(results, parseErr)
		for _, failure := range datagramFailures(parseErr) {
			if bundled && !conn.bundleHeaderNegotiated(failure.Header, addr) {
				continue
			}
			if h := failure.Header; h != nil && !h.IsRequest() {
				conn.failResponse(h.Type, h.Sequence(), addr, failure.Err)
			}
			var version *message.UnsupportedVersionError
			var decode *ie.DecodeError
			var length *message.InvalidLengthError
			switch {
			case errors.As(failure.Err, &version):
				// TS 29.244 V20.1.0 clauses 7.6.2 and 7.4.4.7.
				if err := conn.SendMessage(message.NewVersionNotSupportedResponse(version.Header.Sequence()), addr); err != nil {
					results = append(results, err)
				}
			case failure.Header != nil && errors.As(failure.Err, &length) && failure.Header.IsRequest():
				// TS 29.244 V20.1.0 clause 7.6.3. Heartbeat has no Cause
				// IE and is discarded, consistent with 7.6.6/7.6.7 exemptions.
				if failure.Header.Type == message.MsgTypeHeartbeatRequest {
					continue
				}
				conn.stateMu.RLock()
				seid := uint64(0)
				if assoc := conn.sessionAssociation(failure.Header.SEID); assoc != nil {
					seid = assoc.Sessions[failure.Header.SEID].RemoteSEID
				}
				response := conn.errorResponse(failure.Header.Type+1, seid, failure.Header.Sequence(), ie.CauseInvalidLength, nil)
				conn.stateMu.RUnlock()
				if response != nil {
					if err := conn.SendMessage(response, addr); err != nil {
						results = append(results, err)
					}
				}
			case failure.Header != nil && failure.Header.IsRequest() && errors.As(failure.Err, &decode) && failure.Header.Type != message.MsgTypeHeartbeatRequest:
				// TS 29.244 V20.1.0 clause 7.6.7: malformed IE framing requires Cause 68.
				var offending *ie.IE
				if !decode.TypeUnknown {
					offending = ie.NewOffendingIE(decode.Type)
				}
				conn.stateMu.RLock()
				response := conn.errorResponse(failure.Header.Type+1, conn.peerSessionSEID(failure.Header.SEID, conn.sessionOwnerID(failure.Header.SEID)), failure.Header.Sequence(), ie.CauseInvalidLength, offending)
				conn.stateMu.RUnlock()
				if response != nil {
					if err := conn.SendMessage(response, addr); err != nil {
						results = append(results, err)
					}
				}
			}
		}
	}
	// Capture association identity before any sibling can delete its last
	// session. A single peer entity's bundle retains that admission context.
	contexts := make([]*NodeAssociation, len(incoming))
	if bundled {
		var unique *NodeAssociation
		conflict := false
		for i, msg := range incoming {
			contexts[i] = conn.bundleAssociation(msg, addr)
			if contexts[i] != nil {
				if unique != nil && unique != contexts[i] {
					conflict = true
				}
				unique = contexts[i]
			}
		}
		if !conflict && unique != nil {
			for i, msg := range incoming {
				if contexts[i] == nil && (msg.MessageType() == message.MsgTypeSessionModificationRequest || msg.MessageType() == message.MsgTypeSessionDeletionRequest) {
					contexts[i] = unique
				}
			}
		}
	}
	for i, incomingMsg := range incoming {
		if bundled && !conn.supportsBundle(contexts[i]) {
			continue
		}
		if err := handlerMap.handleMessage(conn, incomingMsg, buf, addr, local, contexts[i]); err != nil {
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

func (handlerMap PfcpHandlerMap) handleMessage(conn *PfcpConnection, incomingMsg message.Message, buf []byte, addr *net.UDPAddr, local netip.AddrPort, contexts ...*NodeAssociation) error {
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
		conn.stateMu.Lock()
		conn.completeRequestLocked(completed, requestResult{outcome: requestInvalid, err: errors.New("PFCP response has no procedure handler")})
		conn.stateMu.Unlock()
		return nil
	} // Clause 7.6.4: discard unknown types before creating labels.
	PfcpMessageRx.WithLabelValues(incomingMsg.MessageTypeName()).Inc()
	var digest [32]byte
	if incomingMsg.IsRequest() {
		var err error
		digest, err = requestDigest(incomingMsg, buf)
		if err != nil {
			return err
		}
	}
	key := requestKey{peer: addr.String(), sequence: incomingMsg.Sequence(), typ: incomingMsg.MessageType()}
	startTime := time.Now()
	conn.stateMu.Lock()
	if conn.isClosed() {
		conn.completeRequestLocked(completed, requestResult{outcome: requestCanceled, err: net.ErrClosed})
		conn.stateMu.Unlock()
		return net.ErrClosed
	}
	if completed != nil {
		current := conn.GetAssociation(completed.associationID())
		if (completed.association != nil || completed.typ == message.MsgTypeHeartbeatRequest) && current != completed.association {
			conn.completeRequestLocked(completed, requestResult{outcome: requestCanceled, err: errors.New("PFCP association replaced")})
			conn.stateMu.Unlock()
			return nil
		}
		// The requesting procedure receives its terminal result below.
	}
	var outgoing message.Message
	var trace bool
	var handlerErr error
	if !incomingMsg.IsRequest() {
		handlerErr = validateIncomingResponse(incomingMsg)
		// An accepted Report Response identifies the UP session originally
		// addressed by this procedure (TS 29.244 V20.1.0 clause 7.2.2.4.1).
		if handlerErr == nil && incomingMsg.MessageType() == message.MsgTypeSessionReportResponse && completed.localSEID != 0 && incomingMsg.SEID() != completed.localSEID {
			handlerErr = errors.New("PFCP Session Report Response has a different local SEID")
		}
		if handlerErr == nil {
			if report, ok := incomingMsg.(*message.SessionReportResponse); ok {
				handlerErr = conn.validateBufferReportResponseLocked(completed, report)
			}
		}

	}

	if incomingMsg.IsRequest() {
		if failure := validateIncomingRequest(incomingMsg); failure != nil {
			handlerErr = failure
			outgoing = conn.errorResponse(incomingMsg.MessageType()+1, conn.responseSEID(incomingMsg, addr.IP.String()), incomingMsg.Sequence(), failure.cause, ie.NewOffendingIE(failure.offending))
		}
	}

	assoc := conn.associationForMessage(incomingMsg, addr.IP.String())
	var bound *NodeAssociation
	if len(contexts) > 0 && contexts[0] != nil && activeAssociation(conn.associationByID(contexts[0].ID)) == contexts[0] {
		bound = contexts[0]
	}
	if assoc == nil {
		assoc = bound
	}
	entity := conn.incomingEntity(incomingMsg, addr.IP.String())
	// Stateless Heartbeat and Release always bypass capacity (6.2.2.2,
	// 6.2.8.3 NOTE). Replays are checked before session lookup: Deletion may
	// already have removed its context. No new unassociated outcome is cached.
	cacheable := incomingMsg.IsRequest() && incomingMsg.MessageType() != message.MsgTypeHeartbeatRequest && incomingMsg.MessageType() != message.MsgTypeAssociationReleaseRequest && handlerErr == nil
	owner := ""
	if assoc != nil {
		owner = assoc.ID
	}
	if setup, ok := incomingMsg.(*message.AssociationSetupRequest); ok {
		value, _ := setup.NodeID.NodeID()
		owner = nodeIDText(value)
	}
	if cacheable {
		wire, found, err := conn.cachedReply(key, digest, owner)
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
	if handlerErr == nil && incomingMsg.IsRequest() {
		switch incomingMsg.MessageType() {
		case message.MsgTypeSessionEstablishmentRequest, message.MsgTypeSessionModificationRequest, message.MsgTypeSessionDeletionRequest:
			if assoc == nil {
				handlerErr = errNoEstablishedAssociation
				outgoing = conn.errorResponse(incomingMsg.MessageType()+1, conn.responseSEID(incomingMsg, addr.IP.String()), incomingMsg.Sequence(), ie.CauseNoEstablishedPFCPAssociation, nil)
			}
		}
	}
	if handlerErr == nil {
		handlerIdentity := addr.IP.String()
		if assoc != nil && incomingMsg.MessageType() != message.MsgTypeHeartbeatRequest {
			handlerIdentity = assoc.ID
		}
		if completed != nil && completed.typ == message.MsgTypeHeartbeatRequest && completed.association != nil {
			handlerIdentity = completed.association.ID
		}
		outgoing, trace, handlerErr = handler(conn, incomingMsg, handlerIdentity)
		if handlerErr == nil {
			conn.rememberSessionEntity(incomingMsg, outgoing, addr.IP.String())
		}
	}

	waiting, deferred := outgoing.(*usageResponse)
	var wire []byte
	if outgoing != nil && !deferred {
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
	if cacheable {
		current := conn.associationForMessage(incomingMsg, addr.IP.String())
		if current == nil {
			current = assoc
		}
		if current != nil && activeAssociation(conn.associationByID(current.ID)) == current {
			conn.cacheReply(key, digest, wire, entity, current.ID)
		} else {
			conn.discardReply(key, digest)
		}
	}

	if completed != nil && completed.typ == message.MsgTypeAssociationSetupRequest && handlerErr == nil {
		if current := conn.associationForMessage(incomingMsg, addr.IP.String()); current != nil {
			current.UPFeatures = append([]byte(nil), completed.upFeatures...)
			if conn.connectorNodes == nil {
				conn.connectorNodes = make(map[string]string)
			}
			conn.connectorNodes[completed.peer.IP.String()] = current.ID
		}
	}

	if completed != nil {
		conn.completeRequestLocked(completed, responseResult(incomingMsg, handlerErr))
	}
	conn.stateMu.Unlock()
	if completed != nil || incomingMsg.MessageType() == message.MsgTypeAssociationSetupRequest {
		conn.flushBufferReportUpdates()
		conn.flushReportRetries()
	}
	if trace && IsMessageTraceable(incomingMsg.MessageType()) {
		conn.traceMessageAtLocal(buf, addr, local, true)
	}
	UpfMessageRxLatency.WithLabelValues(incomingMsg.MessageTypeName()).Observe(time.Since(startTime).Seconds())
	if deferred {
		copied := *addr
		copied.IP = append(net.IP(nil), addr.IP...)
		go conn.completeUsageResponse(waiting, key, digest, &copied, entity, assoc, trace, startTime)
		return handlerErr
	}
	if wire != nil {
		handlerErr = errors.Join(handlerErr, conn.sendEncoded(wire, outgoing.MessageType(), addr, trace))
	}
	return handlerErr
}

// A normal standalone datagram already has canonical framing. Hash its received
// bytes without allocating another IE tree encoding. Bundles and ignored header
// bits still use the codec to obtain canonical standalone framing (TS 29.244
// V20.1.0 clauses 6.4, 6.5 and 7.2.2.1 through 7.2.2.4.1).
func requestDigest(msg message.Message, wire []byte) ([32]byte, error) {
	if canonicalStandaloneHeader(wire) {
		return sha256.Sum256(wire), nil
	}
	encoded := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(encoded); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func canonicalStandaloneHeader(wire []byte) bool {
	if len(wire) < 8 || wire[0]>>5 != 1 || wire[0]&0x1c != 0 || int(binary.BigEndian.Uint16(wire[2:4]))+4 != len(wire) {
		return false
	}
	if wire[0]&1 == 0 {
		return wire[0]&2 == 0 && wire[7] == 0
	}
	if len(wire) < 16 {
		return false
	}
	if wire[0]&2 != 0 {
		return wire[15]&0x0f == 0
	}
	return wire[15] == 0
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
	// TS 29.244 V20.1.0 table 7.4.4.2-1 and clause 8.2.1: local
	// shutdown has no resources for a new association (Cause 75).
	if conn.ResourceManager.ShuttingDown() || conn.releasing || conn.terminalError != nil {
		return conn.errorResponse(message.MsgTypeAssociationSetupResponse, 0, request.Sequence(), ie.CauseNoResourcesAvailable, nil), true, errors.New("PFCP connection releasing")
	}
	if value, err := request.NodeID.NodeID(); err == nil {
		if old := conn.associationByID(nodeIDText(value)); old != nil && (!old.releaseDeadline.IsZero() || old.cleaning) {
			return conn.errorResponse(message.MsgTypeAssociationSetupResponse, 0, request.Sequence(), ie.CauseNoResourcesAvailable, nil), true, errors.New("PFCP association releasing")
		}
	}
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
	if activeAssociation(assoc) == nil || assoc.ID != nodeIDText(node) {
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
	if conn.ResourceManager.ShuttingDown() || conn.releasing {
		return nil, false, errors.New("association setup canceled during release")
	}
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
	// TS 29.244 V20.1.0 clause 6.2.6.3: a Setup Response does not
	// invoke the CP-initiated replacement procedure of clause 6.2.6.2.2.
	if existing := conn.associationByID(nodeIDText(node)); existing != nil {
		if features, e := response.CPFunctionFeatures.CPFunctionFeatures(); e == nil {
			existing.CPFeatures = append([]byte(nil), features...)
		}
		return nil, true, nil
	}
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

// Negotiation belongs to this association's own Setup/Update exchange, including
// UP-initiated Sxa/Sxb. A datagram bounds work; there is no extra count/size cap.
// TS 29.244 V20.1.0 clause 6.5.
func (conn *PfcpConnection) supportsBundle(assoc *NodeAssociation) bool {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	if assoc == nil || activeAssociation(conn.associationByID(assoc.ID)) != assoc {
		return false
	}
	return (&ie.IE{Type: ie.CPFunctionFeatures, Payload: assoc.CPFeatures}).HasBUNDL() && (&ie.IE{Type: ie.UPFunctionFeatures, Payload: assoc.UPFeatures}).HasBUNDL()
}
func (conn *PfcpConnection) bundleAssociation(msg message.Message, peer *net.UDPAddr) *NodeAssociation {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	if assoc := conn.associationForMessage(msg, peer.IP.String()); assoc != nil {
		return assoc
	}
	conn.transport.mu.Lock()
	defer conn.transport.mu.Unlock()
	if !msg.IsRequest() {
		if req := conn.transport.pending[msg.Sequence()]; req != nil && req.peer.String() == peer.String() && msg.MessageType() == req.typ+1 {
			return activeAssociation(conn.associationByID(req.associationID()))
		}
		return nil
	}
	// Deletion retransmissions retain their association through the replay index
	// even after deleting the last session at an additional CP address (6.4/6.5).
	wire := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(wire); err != nil {
		return nil
	}
	key := requestKey{peer: peer.String(), sequence: msg.Sequence(), typ: msg.MessageType(), digest: sha256.Sum256(wire)}
	if entry, ok := conn.transport.responses[key]; ok {
		return activeAssociation(conn.associationByID(entry.budget.host))
	}
	return nil
}
func (conn *PfcpConnection) bundleHeaderNegotiated(h *message.Header, peer *net.UDPAddr) bool {
	if h == nil || !h.HasSEID() {
		return false
	}
	return conn.supportsBundle(conn.bundleAssociation(message.NewGeneric(h.Type, h.SEID, h.Sequence()), peer))
}

func (conn *PfcpConnection) sessionOwnerID(seid uint64) string {
	if assoc := conn.sessionAssociation(seid); assoc != nil {
		return assoc.ID
	}
	return ""
}
