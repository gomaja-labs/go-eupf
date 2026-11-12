// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"slices"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var errMandatoryIeMissing = fmt.Errorf("mandatory IE missing")
var errNoEstablishedAssociation = fmt.Errorf("no established association")
var errNotAllowedNetworkInstance = fmt.Errorf("not allowed network instance")

func HandlePfcpSessionEstablishmentRequest(conn *PfcpConnection, msg message.Message, addr string) (result message.Message, tracedResult bool, handlerErr error) {
	req := msg.(*message.SessionEstablishmentRequest)
	log.Debug().Msgf("Got Session Establishment Request from: %s.", addr)

	imsi, msisdn := conn.profile.ParseSubscriberData(req.OtherIEs)
	isTraced := conn.NeedSessionTrace(imsi, msisdn)

	remoteSEID, err := validateRequest(req.NodeID, req.CPFSEID)
	if err != nil {
		log.Warn().Msgf("Rejecting Session Establishment Request from: %s (missing NodeID or F-SEID)", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseMandatoryIEMissing)).Inc()
		return message.NewSessionEstablishmentResponse(0, req.Sequence(), conn.profile.NodeID(conn.nodeId), convertErrorToIeCause(err)), isTraced, nil
	}

	association := conn.associationForMessage(req, addr)
	if association == nil {
		log.Warn().Msgf("Rejecting Session Establishment Request from: %s (no association)", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseNoEstablishedPFCPAssociation)).Inc()
		return message.NewSessionEstablishmentResponse(0, req.Sequence(), conn.profile.NodeID(conn.nodeId), ie.NewCause(ie.CauseNoEstablishedPFCPAssociation)), isTraced, nil
	}

	// TS 23.007 V19.2.0 clause 19A: this timestamp belongs to the
	// CP F-SEID IP address, not necessarily the datagram's source address.
	if req.RecoveryTimeStamp != nil {
		if stamp, err := req.RecoveryTimeStamp.RecoveryTimeStamp(); err == nil {
			entity := sessionEntity(req, addr)
			if _, exists := association.recoveries[entity]; !exists && len(association.recoveries) >= 1024 {
				return message.NewSessionEstablishmentResponse(remoteSEID.SEID, req.Sequence(), ie.NewCause(ie.CauseNoResourcesAvailable)), isTraced, nil
			}
			previous := association.recoveries[entity]
			if !conn.observeEntityRecovery(association.ID, entity, stamp, true) {
				if stamp.After(previous) {
					return message.NewSessionEstablishmentResponse(remoteSEID.SEID, req.Sequence(), ie.NewCause(ie.CauseSystemFailure)), isTraced, nil
				}
				return nil, isTraced, nil
			}
		}
	}

	localSEID := conn.newLocalSEID()
	if localSEID == 0 {
		return message.NewSessionEstablishmentResponse(remoteSEID.SEID, req.Sequence(), ie.NewCause(ie.CauseNoResourcesAvailable)), isTraced, nil
	}
	session := NewSession(localSEID, remoteSEID.SEID, imsi, msisdn, isTraced)
	session.CPFSEIDIPv4, session.CPFSEIDIPv6 = slices.Clone(remoteSEID.IPv4Address), slices.Clone(remoteSEID.IPv6Address)
	printSessionEstablishmentRequest(req, conn.profile)

	if req.SNSSAI != nil || requestHasQFI(req.CreateQER) {
		session.Is5G = true
	}

	logger := log.With().
		Uint64("LocalSEID", session.LocalSEID).
		Uint64("RemoteSEID", session.RemoteSEID).
		Logger()

	start, finish := conn.prepareSessionMutation(session)
	defer func() {
		if err := finish(false); err != nil {
			logger.Error().Err(err).Msg("Restore rejected session transaction")
			result = message.NewSessionEstablishmentResponse(session.RemoteSEID, req.Sequence(), ie.NewCause(ie.CauseSystemFailure))
			handlerErr = nil
		}
	}()

	createdPDRs := make([]SPDRInfo, 0)
	pdrContext := NewPDRCreationContext(session, conn.ResourceManager)
	pdrContext.N3Address, pdrContext.N9Address = conn.sessionN3Address(session), cloneIP(conn.n9Address)
	pdrContext.Restoration = req.PFCPSEReqFlags.HasRESTI()
	operationPool := NewOperationPool()
	operationPool.Before = start
	operationPool.Publish = func() error {
		if err := conn.bindAssignedAddresses(session); err != nil {
			return err
		}
		return conn.bindSessionReplies(session)
	}

	err = processEstablishmentRequestRules(conn, logger, req, operationPool, pdrContext, session, &createdPDRs)
	if err != nil {
		logger.Warn().Msgf("Rejecting Session Establishment Request: (error in applying IEs): %s", err)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		if pdrContext.Restoration && (errors.Is(err, service.ErrResourceCollision) || errors.Is(err, ebpf.ErrKeyOwned)) {
			err = &requestIEError{ie.CauseSessionRestorationResourceUnavailable, 0, err}
		}
		return message.NewSessionEstablishmentResponse(remoteSEID.SEID, req.Sequence(), append([]*ie.IE{conn.profile.NodeID(conn.nodeId)}, ruleFailureIEs(err)...)...), isTraced, nil
	}

	logger.Debug().Msgf("session rules before commit: \n\tQER%+v, \n\tFAR%+v, \n\tURR%+v, \n\tPDR%+v", session.QERs, session.FARs, session.URRs, session.PDRs)

	if err := operationPool.Commit(); err != nil {
		logger.Warn().Msgf("Session Establishment Request from %s failed, rolling back", addr)
		logger.Debug().Msgf("session rules after failed commit: \n\tQER%+v, \n\tFAR%+v, \n\tURR%+v, \n\tPDR%+v", session.QERs, session.FARs, session.URRs, session.PDRs)
		if pdrContext.Restoration && (errors.Is(err, service.ErrResourceCollision) || errors.Is(err, ebpf.ErrKeyOwned)) {
			err = &requestIEError{ie.CauseSessionRestorationResourceUnavailable, 0, err}
		}
		return message.NewSessionEstablishmentResponse(remoteSEID.SEID, req.Sequence(), append([]*ie.IE{conn.profile.NodeID(conn.nodeId)}, ruleFailureIEs(err)...)...), isTraced, nil
	}

	logger.Debug().Msgf("session rules arter commit: \n\tQER%+v, \n\tFAR%+v, \n\tURR%+v, \n\tPDR%+v", session.QERs, session.FARs, session.URRs, session.PDRs)

	conn.reconcileSessionResources(session)
	if err := finish(true); err != nil {
		return message.NewSessionEstablishmentResponse(session.RemoteSEID, req.Sequence(), ie.NewCause(ie.CauseSystemFailure)), isTraced, nil
	}

	association.Sessions[localSEID] = session

	additionalIEs := []*ie.IE{
		conn.profile.NodeID(conn.nodeId),
		ie.NewCause(ie.CauseRequestAccepted),
		conn.localFSEID(localSEID),
	}

	defaultN3Address := conn.sessionN3Address(session)
	defaultN9Address := conn.n9Address

	pdrIEs := processCreatedPDRs(createdPDRs, cloneIP(defaultN3Address), cloneIP(defaultN9Address))
	additionalIEs = append(additionalIEs, pdrIEs...)

	// Send SessionEstablishmentResponse
	estResp := message.NewSessionEstablishmentResponse(remoteSEID.SEID, req.Sequence(), additionalIEs...)

	if extraIEs := conn.profile.SessionEstablishmentResponseAdditionalIEs(localSEID, cloneIP(conn.nodeAddrV4.Addr().AsSlice())); len(extraIEs) > 0 {
		estResp.OtherIEs = append(estResp.OtherIEs, extraIEs...)

	}

	PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRequestAccepted)).Inc()
	logger.Debug().Msgf("Session Establishment Request from %s accepted.", addr)

	return estResp, isTraced, nil
}

func HandlePfcpSessionDeletionRequest(conn *PfcpConnection, msg message.Message, addr string) (result message.Message, tracedResult bool, handlerErr error) {
	req := msg.(*message.SessionDeletionRequest)
	log.Debug().Msgf("Got Session Deletion Request from: %s. \n", addr)

	association := conn.associationForMessage(req, addr)
	if association == nil {
		log.Warn().Msgf("Rejecting Session Deletion Request from: %s (no association)", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseNoEstablishedPFCPAssociation)).Inc()
		return message.NewSessionDeletionResponse(0, req.Sequence(), ie.NewCause(ie.CauseNoEstablishedPFCPAssociation)), false, nil
	}
	printSessionDeleteRequest(req)

	session, ok := association.Sessions[req.SEID()]
	if !ok {
		log.Warn().Msgf("Rejecting Session Deletion Request from: %s (unknown SEID)", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseSessionContextNotFound)).Inc()
		return message.NewSessionDeletionResponse(0, req.Sequence(), ie.NewCause(ie.CauseSessionContextNotFound)), false, nil
	}

	session = cloneSession(session)

	logger := log.With().
		Uint64("LocalSEID", session.LocalSEID).
		Uint64("RemoteSEID", session.RemoteSEID).
		Logger()

	traced := session.IsSessionTraced()

	start, finish := conn.prepareSessionMutation(session)
	defer func() {
		if err := finish(false); err != nil {
			logger.Error().Err(err).Msg("Restore rejected session transaction")
			result = message.NewSessionDeletionResponse(session.RemoteSEID, req.Sequence(), ie.NewCause(ie.CauseSystemFailure))
			handlerErr = nil
		}
	}()

	operationPool := NewOperationPool()
	operationPool.Before = start
	deletedURRs := make([]*ie.IE, 0, len(session.URRs))
	pdrContext := NewPDRCreationContext(session, conn.ResourceManager)
	pdrContext.N3Address, pdrContext.N9Address = conn.sessionN3Address(session), cloneIP(conn.n9Address)

	err := processDeletionRequestRules(conn, logger, operationPool, pdrContext, session, &deletedURRs)
	if err != nil {
		logger.Warn().Msgf("Session Deletion Request from %s failed, rolling back", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return message.NewSessionDeletionResponse(session.RemoteSEID, req.Sequence(), ruleFailureIEs(err)...), traced, nil
	}

	if err := operationPool.Commit(); err != nil {
		logger.Warn().Msgf("Session Deletion Request from %s failed, rolling back", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return message.NewSessionDeletionResponse(session.RemoteSEID, req.Sequence(), ruleFailureIEs(err)...), traced, nil
	}

	conn.ReleaseResources(session.LocalSEID)
	if err := finish(true); err != nil {
		return message.NewSessionDeletionResponse(session.RemoteSEID, req.Sequence(), ie.NewCause(ie.CauseSystemFailure)), traced, nil
	}

	additionalIEs := []*ie.IE{
		ie.NewCause(ie.CauseRequestAccepted),
	}
	if len(deletedURRs) != 0 {
		additionalIEs = append(additionalIEs, deletedURRs...)
	}

	logger.Debug().Msgf("Deleting session: %d", req.SEID())
	delete(association.Sessions, req.SEID())

	conn.ReleaseResources(req.SEID())

	PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRequestAccepted)).Inc()
	delResp := message.NewSessionDeletionResponse(session.RemoteSEID, req.Sequence(), additionalIEs...)

	return delResp, traced, nil
}

func HandlePfcpSessionModificationRequest(conn *PfcpConnection, msg message.Message, addr string) (result message.Message, tracedResult bool, handlerErr error) {
	req := msg.(*message.SessionModificationRequest)
	log.Debug().Msgf("Got Session Modification Request from: %s. \n", addr)

	log.Debug().Msgf("Finding association for %s", addr)
	association := conn.associationForMessage(req, addr)
	if association == nil {
		log.Warn().Msgf("Rejecting Session Modification Request from: %s (no association)", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseNoEstablishedPFCPAssociation)).Inc()
		return message.NewSessionModificationResponse(req.SEID(), req.Sequence(), ie.NewCause(ie.CauseNoEstablishedPFCPAssociation)), false, nil
	}

	log.Debug().Msgf("Finding session %d", req.SEID())
	session, ok := association.Sessions[req.SEID()]
	if !ok {
		log.Warn().Msgf("Rejecting Session Modification Request from: %s (unknown SEID)", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseSessionContextNotFound)).Inc()
		return message.NewSessionModificationResponse(0, req.Sequence(), ie.NewCause(ie.CauseSessionContextNotFound)), false, nil
	}

	session = cloneSession(session)
	session.Is5G = session.Is5G || requestHasQFI(req.CreateQER) || requestHasQFI(req.UpdateQER)

	logger := log.With().
		Uint64("LocalSEID", session.LocalSEID).
		Uint64("RemoteSEID", session.RemoteSEID).
		Logger()

	// This IE shall be present if the CP function decides to change its F-SEID for the PFCP session. The UP function
	// shall use the new CP F-SEID for subsequent PFCP Session related messages for this PFCP Session
	newRemoteSEID := session.RemoteSEID
	if req.CPFSEID != nil {
		remoteSEID, err := req.CPFSEID.FSEID()
		if err == nil {
			newRemoteSEID = remoteSEID.SEID
		}
	}

	traced := session.IsSessionTraced()

	printSessionModificationRequest(req, conn.profile)

	start, finish := conn.prepareSessionMutation(session)
	defer func() {
		if err := finish(false); err != nil {
			logger.Error().Err(err).Msg("Restore rejected session transaction")
			result = message.NewSessionModificationResponse(session.RemoteSEID, req.Sequence(), ie.NewCause(ie.CauseSystemFailure))
			handlerErr = nil
		}
	}()

	createdPDRs := make([]SPDRInfo, 0, len(req.CreatePDR))
	updatedPDRs := make([]SPDRInfo, 0, len(req.UpdatePDR))
	removedURRs := make([]*ie.IE, 0, len(req.RemoveURR))
	pdrContext := NewPDRCreationContext(session, conn.ResourceManager)
	pdrContext.N3Address, pdrContext.N9Address = conn.sessionN3Address(session), cloneIP(conn.n9Address)
	operationPool := NewOperationPool()
	operationPool.Before = start
	operationPool.Publish = func() error {
		if err := conn.bindAssignedAddresses(session); err != nil {
			return err
		}
		return conn.bindSessionReplies(session)
	}

	err := processModificationRequestRules(conn, logger, operationPool, pdrContext, req, &createdPDRs, &updatedPDRs, &removedURRs, session)
	if err != nil {
		logger.Warn().Msgf("Rejecting Session Modification Request from: %s (failed to apply rules)", err)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return sessionFailureResponse(req, session.RemoteSEID, err), traced, nil
	}

	if err := operationPool.Commit(); err != nil {
		logger.Warn().Msgf("Rejecting Session Modification Request from: %s (failed to apply rules)", err)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return sessionFailureResponse(req, session.RemoteSEID, err), traced, nil
	}

	conn.reconcileSessionResources(session)
	if err := finish(true); err != nil {
		return message.NewSessionModificationResponse(session.RemoteSEID, req.Sequence(), ie.NewCause(ie.CauseSystemFailure)), traced, nil
	}

	// TS 29.244 V20.1.0 clause 6.3.3.3: rejected requests discard every
	// context update, including the CP F-SEID used for subsequent messages.
	session.RemoteSEID = newRemoteSEID
	if req.CPFSEID != nil {
		if fields, err := req.CPFSEID.FSEID(); err == nil {
			session.CPFSEIDIPv4, session.CPFSEIDIPv6 = slices.Clone(fields.IPv4Address), slices.Clone(fields.IPv6Address)
			association.sessionEntities[req.SEID()] = session.controlIP(conn).String()
		}
	}
	association.Sessions[req.SEID()] = session

	additionalIEs := []*ie.IE{
		ie.NewCause(ie.CauseRequestAccepted),
	}

	defaultN3Address := conn.sessionN3Address(session)
	defaultN9Address := conn.n9Address

	pdrIEs := processCreatedPDRs(createdPDRs, cloneIP(defaultN3Address), cloneIP(defaultN9Address))
	additionalIEs = append(additionalIEs, pdrIEs...)
	additionalIEs = append(additionalIEs, processUpdatedPDRs(updatedPDRs, cloneIP(defaultN3Address), cloneIP(defaultN9Address))...)
	if len(removedURRs) != 0 {
		additionalIEs = append(additionalIEs, removedURRs...)
	}

	// Send SessionEstablishmentResponse
	modResp := message.NewSessionModificationResponse(session.RemoteSEID, req.Sequence(), additionalIEs...)
	PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRequestAccepted)).Inc()

	return modResp, traced, nil
}

// ruleFailure identifies a rule that could not be stored or applied.
// TS 29.244 V20.1.0 clauses 6.3.2.3, 6.3.3.3 and 8.2.80.
type ruleFailure struct {
	kind uint8
	id   uint32
	err  error
}

func (failure *ruleFailure) Error() string {
	return fmt.Sprintf("rule type %d ID %d: %v", failure.kind, failure.id, failure.err)
}

func (failure *ruleFailure) Unwrap() error { return failure.err }

func ruleFailureIEs(err error) []*ie.IE {
	cause := ie.CauseRuleCreationModificationFailure
	if errors.Is(err, ebpf.ErrRuleCapacity) || errors.Is(err, service.ErrResourceExhausted) {
		cause = ie.CauseNoResourcesAvailable
	}
	if errors.Is(err, ebpf.ErrUnsupportedRuleContent) {
		cause = ie.CauseServiceNotSupported
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EIO) || errors.Is(err, syscall.EBADF) {
		cause = ie.CauseSystemFailure
	}
	if errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.ENOSPC) {
		cause = ie.CauseNoResourcesAvailable
	}
	var incorrect *requestIEError
	if errors.As(err, &incorrect) {
		cause = incorrect.cause
	}
	result := []*ie.IE{ie.NewCause(cause)}
	if incorrect != nil && incorrect.offending != 0 {
		result = append(result, ie.NewOffendingIE(incorrect.offending))
	}
	var failure *ruleFailure
	if errors.As(err, &failure) {
		result = append(result, ie.NewFailedRuleID(failure.kind, failure.id))
	}
	return result
}

func convertErrorToIeCause(err error) *ie.IE {
	switch {
	case errors.Is(err, errMandatoryIeMissing):
		return ie.NewCause(ie.CauseMandatoryIEMissing)
	case errors.Is(err, errNoEstablishedAssociation):
		return ie.NewCause(ie.CauseNoEstablishedPFCPAssociation)
	default:
		log.Info().Msgf("Unknown error: %s", err.Error())
		return ie.NewCause(ie.CauseRequestRejected)
	}
}

func validateRequest(nodeId *ie.IE, cpfseid *ie.IE) (fseid *ie.FSEIDFields, err error) {
	if nodeId == nil || cpfseid == nil {
		return nil, errMandatoryIeMissing
	}

	_, err = nodeId.NodeID()
	if err != nil {
		return nil, errMandatoryIeMissing
	}

	fseid, err = cpfseid.FSEID()
	if err != nil {
		return nil, errMandatoryIeMissing
	}

	return fseid, nil
}

func findEnterpriseSpecificIEindex(ieArr []*ie.IE, ieType ie.IEType, ieEnterpriseID uint16) int {
	arrIndex := slices.IndexFunc(ieArr, func(ie *ie.IE) bool {
		return ie.Type == ieType && ie.EnterpriseID == ieEnterpriseID
	})
	return arrIndex
}

func causeToString(cause uint8) string {
	switch cause {
	case ie.CauseRequestAccepted:
		return "RequestAccepted"
	case ie.CauseRequestRejected:
		return "RequestRejected"
	case ie.CauseSessionContextNotFound:
		return "SessionContextNotFound"
	case ie.CauseMandatoryIEMissing:
		return "MandatoryIEMissing"
	case ie.CauseConditionalIEMissing:
		return "ConditionalIEMissing"
	case ie.CauseInvalidLength:
		return "InvalidLength"
	case ie.CauseMandatoryIEIncorrect:
		return "MandatoryIEIncorrect"
	case ie.CauseInvalidForwardingPolicy:
		return "InvalidForwardingPolicy"
	case ie.CauseInvalidFTEIDAllocationOption:
		return "InvalidFTEIDAllocationOption"
	case ie.CauseNoEstablishedPFCPAssociation:
		return "NoEstablishedPFCPAssociation"
	case ie.CauseRuleCreationModificationFailure:
		return "RuleCreationModificationFailure"
	case ie.CausePFCPEntityInCongestion:
		return "PFCPEntityInCongestion"
	case ie.CauseNoResourcesAvailable:
		return "NoResourcesAvailable"
	case ie.CauseServiceNotSupported:
		return "ServiceNotSupported"
	case ie.CauseSystemFailure:
		return "SystemFailure"
	case ie.CauseRedirectionRequested:
		return "RedirectionRequested"
	default:
		return "UnknownCause"
	}
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func composeFarInfo(far *ie.IE, farInfo ebpf.FarInfo, profile PfcpProfile) (ebpf.FarInfo, error) {
	var action, outer, marking *ie.IE
	switch far.Type {
	case ie.CreateFAR:
		f, err := far.CreateFAR()
		if err != nil {
			return farInfo, err
		}
		action = f.ApplyAction
		if f.ForwardingParameters != nil {
			forward, err := f.ForwardingParameters.ForwardingParameters()
			if err != nil {
				return farInfo, err
			}
			outer, marking = forward.OuterHeaderCreation, forward.TransportLevelMarking
		}
	case ie.UpdateFAR:
		f, err := far.UpdateFAR()
		if err != nil {
			return farInfo, err
		}
		action = f.ApplyAction
		if f.UpdateForwardingParameters != nil {
			forward, err := f.UpdateForwardingParameters.UpdateForwardingParameters()
			if err != nil {
				return farInfo, err
			}
			outer, marking = forward.OuterHeaderCreation, forward.TransportLevelMarking
		}
	default:
		return farInfo, &ie.InvalidTypeError{Type: far.Type}
	}
	if action != nil {
		flags, err := action.ApplyAction()
		if err != nil {
			return farInfo, err
		}
		farInfo.Action = flags[0]
	}
	// TS 29.244 V20.1.0 clauses 5.6.3 and 8.1.2: null removes a provisioned value.
	if far.Type == ie.UpdateFAR && isNullIE(outer) {
		farInfo.OuterHeaderCreation, farInfo.Teid, farInfo.RemoteIP = 0, 0, 0
	} else if outer != nil {
		fields, err := profile.ParseOuterHeaderCreation(outer)
		if err != nil {
			return farInfo, err
		}
		if fields.OuterHeaderCreation != 1 || fields.Description != 0x100 && fields.Description != 0 || fields.IPv6Address != nil || fields.CTag != 0 || fields.STag != 0 || fields.PortNumber != 0 {
			return farInfo, unsupportedRuleIE(ie.OuterHeaderCreation)
		}
		farInfo.OuterHeaderCreation, farInfo.Teid = fields.OuterHeaderCreation, fields.Teid
		if fields.IPv4Address != nil {
			farInfo.RemoteIP = binary.LittleEndian.Uint32(fields.IPv4Address)
		}
		if fields.IPv6Address != nil {
			return farInfo, unsupportedRuleIE(ie.OuterHeaderCreation)
		}
	}
	if far.Type == ie.UpdateFAR && isNullIE(marking) {
		farInfo.TransportLevelMarking = 0
	} else if marking != nil {
		value, err := marking.TransportLevelMarking()
		if err != nil {
			return farInfo, err
		}
		farInfo.TransportLevelMarking = binary.BigEndian.Uint16(value)
	}
	return farInfo, nil
}

func updateQer(qerInfo *ebpf.QerInfo, qer *ie.IE, profile PfcpProfile) {

	var gate, mbr, rqi *ie.IE
	switch qer.Type {
	case ie.CreateQER:
		f, err := qer.CreateQER()
		if err != nil {
			return
		}
		gate, mbr, rqi = f.GateStatus, f.MaximumBitrate, f.ReflectiveQoS
	case ie.UpdateQER:
		f, err := qer.UpdateQER()
		if err != nil {
			return
		}
		gate, mbr, rqi = f.GateStatus, f.MaximumBitrate, f.ReflectiveQoS
	default:
		return
	}
	// TS 29.244 V20.1.0 clause 5.6.3: absent values preserve the old rule; null values remove them.
	if qer.Type == ie.UpdateQER && isNullIE(gate) {
		qerInfo.GateStatusDL, qerInfo.GateStatusUL = 0, 0
	}
	if qer.Type == ie.UpdateQER && isNullIE(mbr) {
		qerInfo.MaxBitrateDL, qerInfo.MaxBitrateUL = 0, 0
	}
	gateStatusDL, err := gate.GateStatusDL()
	if err == nil {
		qerInfo.GateStatusDL = gateStatusDL
	}
	gateStatusUL, err := gate.GateStatusUL()
	if err == nil {
		qerInfo.GateStatusUL = gateStatusUL
	}
	maxBitrateDL, err := mbr.MBRDL()
	if err == nil {
		qerInfo.MaxBitrateDL = maxBitrateDL * 1000
	}
	maxBitrateUL, err := mbr.MBRUL()
	if err == nil {
		qerInfo.MaxBitrateUL = maxBitrateUL * 1000
	}
	if qfi, ok := profile.ParseQFI(qer); ok {
		qerInfo.Qfi = qfi
		qfiIE, _, _ := qerQFI(qer)
		qerInfo.QFIPresent = qfiIE != nil && !isNullIE(qfiIE)
	}

	if rqi != nil {
		if isNullIE(rqi) {
			qerInfo.RQI = 0
		} else if value, err := rqi.RQI(); err == nil {
			qerInfo.RQI = value
		}
	}
	qerInfo.Dscp = config.Conf.GetDscpMarkByQci(qerInfo.Qfi)
}

// GetTransportLevelMarking reads the forwarding parameters as the value/mask pair used by the data plane.
func GetTransportLevelMarking(far *ie.IE) (uint16, error) {
	switch far.Type {
	case ie.CreateFAR:
		f, err := far.CreateFAR()
		if err != nil {
			return 0, err
		}
		forward, err := f.ForwardingParameters.ForwardingParameters()
		if err != nil {
			return 0, err
		}
		value, err := forward.TransportLevelMarking.TransportLevelMarking()
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint16(value), nil
	case ie.UpdateFAR:
		f, err := far.UpdateFAR()
		if err != nil {
			return 0, err
		}
		forward, err := f.UpdateForwardingParameters.UpdateForwardingParameters()
		if err != nil {
			return 0, err
		}
		value, err := forward.TransportLevelMarking.TransportLevelMarking()
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint16(value), nil
	default:
		return 0, &ie.InvalidTypeError{Type: far.Type}
	}
}

func updateUrr(info *ebpf.UrrInfo, rule *ie.IE) {
	var volume, triggers *ie.IE
	switch rule.Type {
	case ie.CreateURR:
		fields, err := rule.CreateURR()
		if err != nil {
			return
		}
		volume, triggers = fields.VolumeThreshold, fields.ReportingTriggers
	case ie.UpdateURR:
		fields, err := rule.UpdateURR()
		if err != nil {
			return
		}
		volume, triggers = fields.VolumeThreshold, fields.ReportingTriggers
	}
	if triggers != nil {
		info.VolumeTrigger = triggers.HasVOLTH()
	}
	if volume != nil {
		if isNullIE(volume) {
			info.VolumeThreshold = 0
		} else if value, err := volume.VolumeThreshold(); err == nil {
			info.VolumeThreshold = value.TotalVolume
			info.VolumeReported = false
		}
	}
}

func HandlePfcpSessionReportResponse(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	srr := msg.(*message.SessionReportResponse)
	log.Debug().Msgf("Got Session Report Response from: %s.", addr)

	printSessionReportResponse(srr)

	return nil, true, nil
}

func processEstablishmentRequestRules(
	conn *PfcpConnection,
	logger zerolog.Logger,
	req *message.SessionEstablishmentRequest,
	operationPool *OperationPool,
	pdrContext *PDRCreationContext,
	session *Session,
	createdPDRs *[]SPDRInfo,
) error {
	if err := validateSessionCapability(req); err != nil {
		return err
	}
	if err := validateSessionRuleIDs(session, req.CreatePDR, req.CreateFAR, req.CreateQER, req.CreateURR); err != nil {
		return err
	}
	if err := validateRuleNetworkInstances(conn, req.CreatePDR, req.CreateFAR); err != nil {
		return err
	}
	mapOperations := conn.mapOperations

	err := createFARs(req.CreateFAR, mapOperations, session, operationPool, logger, conn.profile)
	if err != nil {
		return err
	}
	err = createQERs(req.CreateQER, mapOperations, session, operationPool, logger, conn.profile)
	if err != nil {
		return err
	}
	err = createURRs(req.CreateURR, mapOperations, session, operationPool, logger)
	if err != nil {
		return err
	}

	imsi, msisdn := conn.profile.ParseSubscriberData(req.OtherIEs)
	isTraced := conn.NeedSessionTrace(imsi, msisdn)

	err = createPDRs(req.CreatePDR, session, operationPool, logger, isTraced, conn, pdrContext, createdPDRs)
	if err != nil {
		return err
	}

	return validateSessionRuleShapes(conn, session)
}

func processDeletionRequestRules(
	conn *PfcpConnection,
	logger zerolog.Logger,
	operationPool *OperationPool,
	pdrContext *PDRCreationContext,
	session *Session,
	deletedURRs *[]*ie.IE,
) error {
	mapOperations := conn.mapOperations

	for _, pdr := range session.PDRs {
		operationPool.AddRule(ie.RuleIDTypePDR, pdr.PdrID, Operation{
			Detach: func(pdr SPDRInfo) func() error {
				return func() error {
					return pdrContext.deletePDR(pdr, mapOperations)
				}
			}(pdr),
		})
	}

	for farID, far := range session.FARs {
		operationPool.AddRule(ie.RuleIDTypeFAR, farID, Operation{
			Detach: func() error { return mapOperations.DetachRule(1, far.GlobalId) },
			Retire: func(far SFarInfo) func() error {
				return func() error {
					return mapOperations.DeleteFar(far.GlobalId)
				}
			}(far),
		})
	}

	for qerID, qer := range session.QERs {
		operationPool.AddRule(ie.RuleIDTypeQER, qerID, Operation{
			Detach: func() error { return mapOperations.DetachRule(2, qer.GlobalId) },
			Retire: func(qer SQerInfo) func() error {
				return func() error {
					return mapOperations.DeleteQer(qer.GlobalId)
				}
			}(qer),
		})
	}

	for urrID, urr := range session.URRs {
		operationPool.AddRule(ie.RuleIDTypeURR, urrID, Operation{
			Detach: func() error { return mapOperations.DetachRule(3, urr.GlobalId) },
			Retire: func(urrID uint32, urr SUrrInfo) func() error {
				return func() error {
					data, err := mapOperations.DeleteUrr(urr.GlobalId)
					if err != nil {
						return err
					}

					session.URRs[urrID] = SUrrInfo{
						UrrInfo:         urr.UrrInfo,
						GlobalId:        urr.GlobalId,
						ReportSeqNumber: urr.ReportSeqNumber + 1,
					}

					uplink := data.UplinkVolume - urr.UrrInfo.UplinkVolume
					downlink := data.DownlinkVolume - urr.UrrInfo.DownlinkVolume

					deletionReportIEs := append([]*ie.IE{
						ie.NewURRID(urrID),
						conn.profile.URSEQN(urr.ReportSeqNumber),
						ie.NewUsageReportTrigger(0, 1<<3, 0),
						ie.NewEndTime(time.Now()),
						ie.NewVolumeMeasurement(0x7, uplink+downlink, uplink, downlink, 0, 0, 0),
					}, conn.profile.UsageReportDeletionVendorIEs()...)
					report := ie.NewUsageReportWithinSessionDeletionResponse(deletionReportIEs...)

					*deletedURRs = append(*deletedURRs, report)

					return nil
				}
			}(urrID, urr),
		})
	}

	return nil
}

func processModificationRequestRules(
	conn *PfcpConnection,
	logger zerolog.Logger,
	operationPool *OperationPool,
	pdrContext *PDRCreationContext,
	req *message.SessionModificationRequest,
	createdPDRs *[]SPDRInfo,
	updatedPDRs *[]SPDRInfo,
	removedURRs *[]*ie.IE,
	session *Session,
) error {
	previousUsageRefs := usageReferences(session)
	if err := validateSessionCapability(req); err != nil {
		return err
	}
	if err := validateSessionRuleIDs(session, req.CreatePDR, req.UpdatePDR, req.RemovePDR,
		req.CreateFAR, req.UpdateFAR, req.RemoveFAR, req.CreateQER, req.UpdateQER, req.RemoveQER,
		req.CreateURR, req.UpdateURR, req.RemoveURR); err != nil {
		return err
	}
	if err := validateRuleNetworkInstances(conn, req.CreatePDR, req.UpdatePDR, req.CreateFAR, req.UpdateFAR); err != nil {
		return err
	}
	mapOperations := conn.mapOperations

	err := createFARs(req.CreateFAR, mapOperations, session, operationPool, logger, conn.profile)
	if err != nil {
		return err
	}
	err = updateFARs(req.UpdateFAR, mapOperations, session, operationPool, logger, conn.profile)
	if err != nil {
		return err
	}
	err = removeFARs(req.RemoveFAR, mapOperations, session, operationPool, logger)
	if err != nil {
		return err
	}

	err = createQERs(req.CreateQER, mapOperations, session, operationPool, logger, conn.profile)
	if err != nil {
		return err
	}
	err = updateQERs(req.UpdateQER, mapOperations, session, operationPool, logger, conn.profile)
	if err != nil {
		return err
	}
	err = removeQERs(req.RemoveQER, mapOperations, session, operationPool, logger)
	if err != nil {
		return err
	}

	err = createURRs(req.CreateURR, mapOperations, session, operationPool, logger)
	if err != nil {
		return err
	}
	err = updateURRs(req.UpdateURR, mapOperations, session, operationPool, logger, conn.profile)
	if err != nil {
		return err
	}
	err = removeURRs(req.RemoveURR, mapOperations, session, operationPool, logger, removedURRs, conn.profile)
	if err != nil {
		return err
	}

	// obtain tracing flag from storage by IMSI or MSISDN
	imsi, msisdn := conn.profile.ParseSubscriberData(req.OtherIEs)
	isTraced := conn.NeedSessionTrace(imsi, msisdn)

	err = createPDRs(req.CreatePDR, session, operationPool, logger, isTraced, conn, pdrContext, createdPDRs)
	if err != nil {
		return err
	}
	err = updatePDRs(req.UpdatePDR, session, operationPool, logger, isTraced, conn, pdrContext, updatedPDRs)
	if err != nil {
		return err
	}
	err = removePDRs(req.RemovePDR, session, operationPool, logger, mapOperations, pdrContext)
	if err != nil {
		return err
	}

	conn.planStoppedUsage(operationPool, session, previousUsageRefs, removedURRs)
	return validateSessionRuleShapes(conn, session)
}

func createFARs(
	FARs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	profile PfcpProfile,
) error {
	for _, far := range FARs {
		fields, decodeErr := far.CreateFAR()
		if decodeErr != nil {
			return decodeErr
		}
		farID, err := fields.FARID.FARID()
		if err != nil {
			return err
		}
		farInfo, err := composeFarInfo(far, ebpf.FarInfo{}, profile)
		if err != nil {
			logger.Warn().Msgf("Error extracting FAR info: %s", err.Error())
			return &ruleFailure{ie.RuleIDTypeFAR, farID, err}
		}

		logger.Info().Msgf("Saving FAR info to session: %d, %+v", farID, farInfo)

		session.NewFar(farID, 0, farInfo)
		operationPool.AddRule(ie.RuleIDTypeFAR, farID, Operation{
			Reserve: func() error {
				id, err := mapOperations.GetNextFAR()
				if err != nil {
					return err
				}
				session.NewFar(farID, id, farInfo)
				return nil
			},
			Apply: func() error { return mapOperations.UpdateFar(session.GetFar(farID).GlobalId, farInfo) },
		})
	}

	return nil
}

func createQERs(
	QERs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	profile PfcpProfile,
) error {
	for _, qer := range QERs {
		fields, decodeErr := qer.CreateQER()
		if decodeErr != nil {
			return decodeErr
		}
		qerID, err := fields.QERID.QERID()
		if err != nil {
			return err
		}

		qerInfo := ebpf.QerInfo{}
		updateQer(&qerInfo, qer, profile)
		if qerInfo.RQI != 0 && !qerInfo.QFIPresent {
			return &ruleFailure{ie.RuleIDTypeQER, qerID, unsupportedRuleIE(ie.RQI)}
		}

		session.NewQer(qerID, 0, qerInfo)
		operationPool.AddRule(ie.RuleIDTypeQER, qerID, Operation{
			Reserve: func() error {
				id, err := mapOperations.GetNextQER()
				if err != nil {
					return err
				}
				session.NewQer(qerID, id, qerInfo)
				return nil
			},
			Apply: func() error { return mapOperations.UpdateQer(session.GetQer(qerID).GlobalId, qerInfo) },
		})
	}

	return nil
}

func createURRs(
	URRs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
) error {
	for _, urr := range URRs {
		fields, decodeErr := urr.CreateURR()
		if decodeErr != nil {
			return decodeErr
		}
		urrID, err := fields.URRID.URRID()
		if err != nil {
			return err
		}

		urrInfo := ebpf.UrrInfo{}

		updateUrr(&urrInfo, urr)
		logger.Info().Msgf("Saving URR info to session: %d, %+v", urrID, urrInfo)

		session.NewUrr(urrID, 0, urrInfo)
		operationPool.AddRule(ie.RuleIDTypeURR, urrID, Operation{
			Reserve: func() error {
				id, err := mapOperations.GetNextURR()
				if err != nil {
					return err
				}
				session.NewUrr(urrID, id, urrInfo)
				return nil
			},
			Apply: func() error { return mapOperations.UpdateUrr(session.GetUrr(urrID).GlobalId, urrInfo) },
		})
	}

	return nil
}

func createPDRs(
	PDRs []*ie.IE,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	isTraced bool,
	conn *PfcpConnection,
	pdrContext *PDRCreationContext,
	createdPDRs *[]SPDRInfo,
) error {
	mapOperations := conn.mapOperations

	for _, pdr := range PDRs {
		fields, decodeErr := pdr.CreatePDR()
		if decodeErr != nil {
			return decodeErr
		}
		// PDR should be created last, because we need to reference FARs and QERs global id
		pdrID, err := fields.PDRID.PDRID()
		if err != nil {
			continue
		}

		pdrCopy := pdr
		spdrInfo := SPDRInfo{
			PdrID:   uint32(pdrID),
			PdrInfo: ebpf.PdrInfo{TraceFlag: isTraced, NRFlag: session.Is5G},
		}

		if err := pdrContext.extractPDR(pdrCopy, &spdrInfo); err != nil {
			return &ruleFailure{ie.RuleIDTypePDR, uint32(pdrID), err}
		}

		if spdrInfo.PCCInfo != nil {
			if _, ok := conn.PCCRules[spdrInfo.PCCInfo.PCCName]; !ok {
				return &ruleFailure{ie.RuleIDTypePDR, uint32(pdrID), fmt.Errorf("predefined rule is not configured")}
			}
			return &ruleFailure{ie.RuleIDTypePDR, uint32(pdrID), unsupportedRuleIE(ie.ActivatePredefinedRules)}
		}

		session.PutPDR(spdrInfo.PdrID, spdrInfo)

		operationPool.AddRule(ie.RuleIDTypePDR, uint32(pdrID), Operation{
			Apply: func() func() error {
				return func() error {
					if err := resolvePDRSlots(&spdrInfo, session); err != nil {
						return err
					}

					logger.Debug().Msgf("pdr: %+v", spdrInfo)
					session.PutPDR(spdrInfo.PdrID, spdrInfo)
					if err := applyPDR(spdrInfo, mapOperations); err != nil {
						return &ruleFailure{ie.RuleIDTypePDR, spdrInfo.PdrID, err}
					}
					*createdPDRs = append(*createdPDRs, spdrInfo)
					return nil
				}
			}(),
		})
	}

	return nil
}

func updateFARs(
	FARs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	profile PfcpProfile,
) error {
	for _, far := range FARs {
		fields, decodeErr := far.UpdateFAR()
		if decodeErr != nil {
			return decodeErr
		}
		farID, err := fields.FARID.FARID()
		if err != nil {
			return err
		}
		oldFar := session.GetFar(farID)

		newFarInfo, err := composeFarInfo(far, oldFar.FarInfo, profile)
		if err != nil {
			logger.Info().Msgf("Error extracting FAR info: %s", err.Error())
			return &ruleFailure{ie.RuleIDTypeFAR, farID, err}
		}

		newFar := oldFar
		newFar.FarInfo = newFarInfo

		session.FARs[farID] = newFar
		operationPool.AddRule(ie.RuleIDTypeFAR, farID, Operation{
			Apply: func() func() error {
				return func() error {
					session.UpdateFar(farID, newFar.FarInfo)
					return mapOperations.UpdateFar(newFar.GlobalId, newFar.FarInfo)
				}
			}(),
		})
	}

	return nil
}

func updateQERs(
	QERs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	profile PfcpProfile,
) error {
	for _, qer := range QERs {
		fields, decodeErr := qer.UpdateQER()
		if decodeErr != nil {
			return decodeErr
		}
		qerID, err := fields.QERID.QERID()
		if err != nil {
			logger.Warn().Msgf("Can't get QER ID: %s", err.Error())
			return err
		}

		oldQer := session.GetQer(qerID)

		newQer := oldQer
		updateQer(&newQer.QerInfo, qer, profile)
		if newQer.QerInfo.RQI != 0 && !newQer.QerInfo.QFIPresent {
			return &ruleFailure{ie.RuleIDTypeQER, qerID, unsupportedRuleIE(ie.RQI)}
		}

		session.QERs[qerID] = newQer
		operationPool.AddRule(ie.RuleIDTypeQER, qerID, Operation{
			Apply: func() func() error {
				return func() error {
					session.UpdateQer(qerID, newQer.QerInfo)
					return mapOperations.UpdateQer(newQer.GlobalId, newQer.QerInfo)
				}
			}(),
		})
	}

	return nil
}
func updateURRs(
	URRs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	profile PfcpProfile,
) error {
	for _, urr := range URRs {
		fields, decodeErr := urr.UpdateURR()
		if decodeErr != nil {
			return decodeErr
		}
		urrID, err := fields.URRID.URRID()
		if err != nil {
			logger.Warn().Msgf("Can't get URR ID: %s", err.Error())
			return err
		}

		oldUrr := session.GetUrr(urrID)

		newUrr := oldUrr
		updateUrr(&newUrr.UrrInfo, urr)

		session.URRs[urrID] = newUrr
		operationPool.AddRule(ie.RuleIDTypeURR, urrID, Operation{
			Apply: func() func() error {
				return func() error {
					session.UpdateUrr(urrID, newUrr.UrrInfo)
					return mapOperations.UpdateUrr(newUrr.GlobalId, newUrr.UrrInfo)
				}
			}(),
		})
	}

	return nil
}

func updatePDRs(
	PDRs []*ie.IE,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	isTraced bool,
	conn *PfcpConnection,
	pdrContext *PDRCreationContext,
	updatedPDRs *[]SPDRInfo,
) error {
	mapOperations := conn.mapOperations

	for _, pdr := range PDRs {
		fields, decodeErr := pdr.UpdatePDR()
		if decodeErr != nil {
			return decodeErr
		}
		pdrID, err := fields.PDRID.PDRID()
		if err != nil {
			return err
		}

		pdrCopy := pdr
		oldInfo := session.GetPDR(pdrID)
		oldInfo.PdrInfo.TraceFlag = isTraced

		newInfo := oldInfo

		if err := pdrContext.extractPDR(pdrCopy, &newInfo); err != nil {
			return &ruleFailure{ie.RuleIDTypePDR, uint32(pdrID), err}
		}

		session.PutPDR(newInfo.PdrID, newInfo)
		operationPool.AddRule(ie.RuleIDTypePDR, uint32(pdrID), Operation{
			Detach: func() error { return pdrContext.deleteReplacedPDR(oldInfo, newInfo, mapOperations) },
			Apply: func(pdrID uint32, newInfo *SPDRInfo) func() error {
				return func() error {
					if err := resolvePDRSlots(newInfo, session); err != nil {
						return err
					}
					if newInfo.PCCInfo != nil {
						return unsupportedRuleIE(ie.ActivatePredefinedRules)
					}

					session.PutPDR(pdrID, *newInfo)
					*updatedPDRs = append(*updatedPDRs, *newInfo)
					if err := applyPDR(*newInfo, mapOperations); err != nil {
						return &ruleFailure{ie.RuleIDTypePDR, newInfo.PdrID, err}
					}

					return nil
				}
			}(uint32(pdrID), &newInfo),
		})
	}

	return nil
}

func removeFARs(
	FARs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
) error {
	for _, far := range FARs {
		fields, decodeErr := far.RemoveFAR()
		if decodeErr != nil {
			return decodeErr
		}
		farID, _ := fields.FARID.FARID()
		logger.Info().Msgf("Removing FAR: %d", farID)
		oldFar, err := session.RemoveFar(farID)
		if err != nil {
			return err
		}

		removeSessionRuleReferences(session, "far", farID, oldFar.GlobalId)

		operationPool.AddRule(ie.RuleIDTypeFAR, farID, Operation{
			Detach: func() error { return mapOperations.DetachRule(1, oldFar.GlobalId) },
			Retire: func() error {
				return mapOperations.DeleteFar(oldFar.GlobalId)
			},
		})
	}

	return nil
}

func removeQERs(
	QERs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
) error {
	for _, qer := range QERs {
		fields, decodeErr := qer.RemoveQER()
		if decodeErr != nil {
			return decodeErr
		}
		qerID, _ := fields.QERID.QERID()
		logger.Debug().Msgf("Removing QER: %d", qerID)
		oldQer, err := session.RemoveQer(qerID)
		if err != nil {
			return err
		}

		removeSessionRuleReferences(session, "qer", qerID, oldQer.GlobalId)

		operationPool.AddRule(ie.RuleIDTypeQER, qerID, Operation{
			Detach: func() error { return mapOperations.DetachRule(2, oldQer.GlobalId) },
			Retire: func() error {
				return mapOperations.DeleteQer(oldQer.GlobalId)
			},
		})
	}

	return nil
}

func removeURRs(
	URRs []*ie.IE,
	mapOperations ebpf.ForwardingPlaneController,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	removedURRs *[]*ie.IE,
	profile PfcpProfile,
) error {
	for _, urr := range URRs {
		fields, decodeErr := urr.RemoveURR()
		if decodeErr != nil {
			return decodeErr
		}
		urrID, _ := fields.URRID.URRID()
		logger.Debug().Msgf("Removing URR: %d", urrID)
		oldUrr, err := session.RemoveUrr(urrID)
		if err != nil {
			return err
		}

		removeSessionRuleReferences(session, "urr", urrID, oldUrr.GlobalId)

		operationPool.AddRule(ie.RuleIDTypeURR, urrID, Operation{
			Detach: func() error { return mapOperations.DetachRule(3, oldUrr.GlobalId) },
			Retire: func() error {
				newReport, err := mapOperations.DeleteUrr(oldUrr.GlobalId)
				if err != nil {
					return err
				}

				uplink := newReport.UplinkVolume - oldUrr.UrrInfo.UplinkVolume
				downlink := newReport.DownlinkVolume - oldUrr.UrrInfo.DownlinkVolume

				report := ie.NewUsageReportWithinSessionModificationResponse(
					ie.NewURRID(urrID),
					profile.URSEQN(oldUrr.ReportSeqNumber),
					ie.NewUsageReportTrigger([]uint8{0, 1 << 3, 0}...),
					ie.NewEndTime(time.Now()),
					ie.NewVolumeMeasurement(0x7,
						uplink+downlink,
						uplink,
						downlink,
						0, 0, 0),
				)

				*removedURRs = append(*removedURRs, report)
				return nil
			},
		})
	}

	return nil
}

func removePDRs(
	PDRs []*ie.IE,
	session *Session,
	operationPool *OperationPool,
	logger zerolog.Logger,
	mapOperations ebpf.ForwardingPlaneController,
	pdrContext *PDRCreationContext,
) error {
	for _, pdr := range PDRs {
		fields, decodeErr := pdr.RemovePDR()
		if decodeErr != nil {
			return decodeErr
		}
		pdrID, _ := fields.PDRID.PDRID()
		pdrKey := uint32(pdrID)

		oldPdr, err := session.RemovePDR(pdrKey)
		if err != nil {
			logger.Warn().Msgf("Can't remove PDR: %s", err.Error())
			return err
		}

		operationPool.AddRule(ie.RuleIDTypePDR, pdrKey, Operation{
			Detach: func() error {
				return pdrContext.deletePDR(oldPdr, mapOperations)
			},
		})
	}

	return nil
}

// TS 29.244 V20.1.0 clause 8.2.37: V4/V6 identify the actual local
// PFCP endpoint family, independently of the user-plane tunnel family.
func (conn *PfcpConnection) localFSEID(seid uint64) *ie.IE {
	address := net.IP(conn.nodeAddrV4.Addr().AsSlice())
	if ip4 := address.To4(); ip4 != nil {
		return ie.NewFSEID(seid, cloneIP(ip4), nil)
	}
	return ie.NewFSEID(seid, nil, cloneIP(address.To16()))
}

func (conn *PfcpConnection) sessionN3Address(session *Session) net.IP {
	if session.Is5G {
		if address := config.Conf.GetN3AdvertisedAddress5G(); address.To4() != nil {
			return cloneIP(address)
		}
	}
	return cloneIP(conn.n3Address)
}
