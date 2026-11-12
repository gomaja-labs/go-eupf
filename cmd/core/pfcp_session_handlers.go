// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"reflect"

	"github.com/gomaja-labs/go-eupf/cmd/config"
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

func HandlePfcpSessionEstablishmentRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
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

	association, ok := conn.NodeAssociations[addr]
	if !ok {
		log.Warn().Msgf("Rejecting Session Establishment Request from: %s (no association)", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseNoEstablishedPFCPAssociation)).Inc()
		return message.NewSessionEstablishmentResponse(0, req.Sequence(), conn.profile.NodeID(conn.nodeId), ie.NewCause(ie.CauseNoEstablishedPFCPAssociation)), isTraced, nil
	}

	localSEID := conn.newLocalSEID()
	session := NewSession(localSEID, remoteSEID.SEID, imsi, msisdn, isTraced)
	printSessionEstablishmentRequest(req, conn.profile)

	if req.SNSSAI != nil {
		session.Is5G = true
	}

	logger := log.With().
		Str("LocalSEID", strconv.Itoa(int(session.LocalSEID))).
		Str("RemoteSEID", strconv.Itoa(int(session.RemoteSEID))).
		Logger()

	createdPDRs := make([]SPDRInfo, 0)
	pdrContext := NewPDRCreationContext(session, conn.ResourceManager)
	operationPool := NewOperationPool()

	err = processEstablishmentRequestRules(conn, logger, req, operationPool, pdrContext, session, &createdPDRs)
	if err != nil {
		logger.Warn().Msgf("Rejecting Session Establishment Request: (error in applying IEs): %s", err)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return message.NewSessionEstablishmentResponse(remoteSEID.SEID, req.Sequence(), append([]*ie.IE{conn.profile.NodeID(conn.nodeId)}, ruleFailureIEs(err)...)...), isTraced, nil
	}

	logger.Debug().Msgf("session rules before commit: \n\tQER%+v, \n\tFAR%+v, \n\tURR%+v, \n\tPDR%+v", session.QERs, session.FARs, session.URRs, session.PDRs)

	if err := operationPool.Commit(); err != nil {
		logger.Warn().Msgf("Session Establishment Request from %s failed, rolling back", addr)
		logger.Debug().Msgf("session rules after failed commit: \n\tQER%+v, \n\tFAR%+v, \n\tURR%+v, \n\tPDR%+v", session.QERs, session.FARs, session.URRs, session.PDRs)
		return message.NewSessionEstablishmentResponse(remoteSEID.SEID, req.Sequence(), append([]*ie.IE{conn.profile.NodeID(conn.nodeId)}, ruleFailureIEs(err)...)...), isTraced, nil
	}

	logger.Debug().Msgf("session rules arter commit: \n\tQER%+v, \n\tFAR%+v, \n\tURR%+v, \n\tPDR%+v", session.QERs, session.FARs, session.URRs, session.PDRs)

	// Reassigning is the best I can think of for now
	association.Sessions[localSEID] = session
	conn.NodeAssociations[addr] = association

	additionalIEs := []*ie.IE{
		conn.profile.NodeID(conn.nodeId),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(localSEID, cloneIP(conn.nodeAddrV4.Addr().AsSlice()), nil),
	}

	defaultN3Address := conn.n3Address
	defaultN9Address := conn.n9Address
	if session.Is5G {
		defaultN3Address = config.Conf.GetN3AdvertisedAddress5G()
	}

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

func HandlePfcpSessionDeletionRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	req := msg.(*message.SessionDeletionRequest)
	log.Debug().Msgf("Got Session Deletion Request from: %s. \n", addr)

	association, ok := conn.NodeAssociations[addr]
	if !ok {
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

	logger := log.With().
		Str("LocalSEID", strconv.Itoa(int(session.LocalSEID))).
		Str("RemoteSEID", strconv.Itoa(int(session.RemoteSEID))).
		Logger()

	traced := session.IsSessionTraced()

	operationPool := NewOperationPool()
	deletedURRs := make([]*ie.IE, 0, len(session.URRs))
	pdrContext := NewPDRCreationContext(session, conn.ResourceManager)

	err := processDeletionRequestRules(conn, logger, operationPool, pdrContext, session, &deletedURRs)
	if err != nil {
		logger.Warn().Msgf("Session Deletion Request from %s failed, rolling back", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return message.NewSessionDeletionResponse(0, req.Sequence(), ie.NewCause(ie.CauseRuleCreationModificationFailure)), traced, err
	}

	if err := operationPool.Commit(); err != nil {
		logger.Warn().Msgf("Session Deletion Request from %s failed, rolling back", addr)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return message.NewSessionDeletionResponse(0, req.Sequence(), ie.NewCause(ie.CauseRuleCreationModificationFailure)), traced, err
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

func HandlePfcpSessionModificationRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
	req := msg.(*message.SessionModificationRequest)
	log.Debug().Msgf("Got Session Modification Request from: %s. \n", addr)

	log.Debug().Msgf("Finding association for %s", addr)
	association, ok := conn.NodeAssociations[addr]
	if !ok {
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

	logger := log.With().
		Str("LocalSEID", strconv.Itoa(int(session.LocalSEID))).
		Str("RemoteSEID", strconv.Itoa(int(session.RemoteSEID))).
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

	createdPDRs := make([]SPDRInfo, 0, len(req.CreatePDR))
	removedURRs := make([]*ie.IE, 0, len(req.RemoveURR))
	pdrContext := NewPDRCreationContext(session, conn.ResourceManager)
	operationPool := NewOperationPool()

	err := processModificationRequestRules(conn, logger, operationPool, pdrContext, req, &createdPDRs, &removedURRs, session)
	if err != nil {
		logger.Warn().Msgf("Rejecting Session Modification Request from: %s (failed to apply rules)", err)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return message.NewSessionModificationResponse(session.RemoteSEID, req.Sequence(), ruleFailureIEs(err)...), traced, nil
	}

	if err := operationPool.Commit(); err != nil {
		logger.Warn().Msgf("Rejecting Session Modification Request from: %s (failed to apply rules)", err)
		PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRuleCreationModificationFailure)).Inc()
		return message.NewSessionModificationResponse(session.RemoteSEID, req.Sequence(), ruleFailureIEs(err)...), traced, nil
	}

	// TS 29.244 V20.1.0 clause 6.3.3.3: rejected requests discard every
	// context update, including the CP F-SEID used for subsequent messages.
	session.RemoteSEID = newRemoteSEID
	association.Sessions[req.SEID()] = session

	additionalIEs := []*ie.IE{
		ie.NewCause(ie.CauseRequestAccepted),
	}

	defaultN3Address := conn.n3Address
	defaultN9Address := conn.n9Address
	if session.Is5G {
		defaultN3Address = config.Conf.GetN3AdvertisedAddress5G()
	}

	pdrIEs := processCreatedPDRs(createdPDRs, cloneIP(defaultN3Address), cloneIP(defaultN9Address))
	additionalIEs = append(additionalIEs, pdrIEs...)
	if len(removedURRs) != 0 {
		additionalIEs = append(additionalIEs, removedURRs...)
	}

	// Send SessionEstablishmentResponse
	modResp := message.NewSessionModificationResponse(session.RemoteSEID, req.Sequence(), additionalIEs...)
	PfcpMessageRxErrors.WithLabelValues(msg.MessageTypeName(), causeToString(ie.CauseRequestAccepted)).Inc()

	return modResp, traced, nil
}

func applySdfFiltersToSession(session *Session, sdfFilters []ebpf.SdfFilter, mapOps ebpf.ForwardingPlaneController) {
	if len(sdfFilters) == 0 {
		return
	}

	for _, spdrInfo := range session.PDRs {
		log.Info().Msgf("Applying SDF Filters: %+v", spdrInfo)
		if spdrInfo.PCCInfo != nil || (spdrInfo.Teid == 0 && spdrInfo.Ipv4 == nil && spdrInfo.Ipv6 == nil) {
			continue
		}

		if spdrInfo.PdrInfo.SdfFilter == nil {
			spdrInfo.PdrInfo.SdfFilter = make([]ebpf.SdfFilter, 0)
		}

		for _, filter := range sdfFilters {
			if len(spdrInfo.PdrInfo.SdfFilter) >= 2 {
				log.Warn().Uint32("pdrID", spdrInfo.PdrID).Msg("sdfFilter is full")
				break
			}
			spdrInfo.PdrInfo.SdfFilter = append(spdrInfo.PdrInfo.SdfFilter, filter)
			spdrInfo.PdrInfo.NotifyFlag = true //FIXME
		}

		session.PutPDR(spdrInfo.PdrID, spdrInfo)
		updatePdrInMap(spdrInfo, mapOps)
	}
}

func removeSdfFiltersFromSession(session *Session, delFilters []ebpf.SdfFilter, mapOps ebpf.ForwardingPlaneController) {
	if len(delFilters) == 0 {
		return
	}

	filterSet := make(map[string]struct{})
	for _, filter := range delFilters {
		filterSet[serializeSdfFilter(filter)] = struct{}{}
	}

	for _, spdrInfo := range session.PDRs {
		if spdrInfo.PCCInfo != nil ||
			(spdrInfo.Teid == 0 && spdrInfo.Ipv4 == nil && spdrInfo.Ipv6 == nil) ||
			spdrInfo.PdrInfo.SdfFilter == nil {
			continue
		}

		newFilters := make([]ebpf.SdfFilter, 0)
		for _, existing := range spdrInfo.PdrInfo.SdfFilter {
			if _, found := filterSet[serializeSdfFilter(existing)]; !found {
				newFilters = append(newFilters, existing)
			}
		}

		spdrInfo.PdrInfo.SdfFilter = newFilters
		session.PutPDR(spdrInfo.PdrID, spdrInfo)
		updatePdrInMap(spdrInfo, mapOps)
	}
}

func updatePdrInMap(spdrInfo SPDRInfo, mapOps ebpf.ForwardingPlaneController) {

	if spdrInfo.Teid > 0 {
		if err := mapOps.UpdatePdrUplink(spdrInfo.Teid, spdrInfo.PdrInfo); err != nil {
			log.Info().Msgf("Can't update GTP PDR: %s", err)
		}
	} else {
		if spdrInfo.Ipv4 != nil {
			if err := mapOps.UpdatePdrDownlink(spdrInfo.Ipv4, spdrInfo.PdrInfo); err != nil {
				log.Info().Msgf("Can't update IPv4 PDR: %s", err)
			}
		}

		if spdrInfo.Ipv6 != nil {
			if err := mapOps.UpdateDownlinkPdrIp6(spdrInfo.Ipv6, spdrInfo.PdrInfo); err != nil {
				log.Info().Msgf("Can't update IPv6 PDR: %s", err)
			}
		}
	}
}

func serializeSdfFilter(filter ebpf.SdfFilter) string {
	t := reflect.TypeOf(filter)
	v := reflect.ValueOf(filter)

	result := ""
	for i := 0; i < t.NumField(); i++ {
		result += fmt.Sprintf("%v|", v.Field(i).Interface())
	}
	return result
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
	result := []*ie.IE{ie.NewCause(ie.CauseRuleCreationModificationFailure)}
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
		farInfo.OuterHeaderCreation, farInfo.Teid = fields.OuterHeaderCreation, fields.Teid
		if fields.IPv4Address != nil {
			farInfo.RemoteIP = binary.LittleEndian.Uint32(fields.IPv4Address)
		}
		if fields.IPv6Address != nil {
			return farInfo, fmt.Errorf("IPv6 not supported yet")
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

	var gate, mbr *ie.IE
	switch qer.Type {
	case ie.CreateQER:
		f, err := qer.CreateQER()
		if err != nil {
			return
		}
		gate, mbr = f.GateStatus, f.MaximumBitrate
	case ie.UpdateQER:
		f, err := qer.UpdateQER()
		if err != nil {
			return
		}
		gate, mbr = f.GateStatus, f.MaximumBitrate
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

func updateUrr(urrInfo *ebpf.UrrInfo, urr *ie.IE) {
	var method, volume, duration *ie.IE
	switch urr.Type {
	case ie.CreateURR:
		f, err := urr.CreateURR()
		if err != nil {
			return
		}
		method, volume, duration = f.MeasurementMethod, f.VolumeThreshold, f.TimeThreshold
	case ie.UpdateURR:
		f, err := urr.UpdateURR()
		if err != nil {
			return
		}
		method, volume, duration = f.MeasurementMethod, f.VolumeThreshold, f.TimeThreshold
	default:
		return
	}
	if urr.Type == ie.UpdateURR && isNullIE(volume) {
		urrInfo.VolumeThreshold = 0
	}
	if urr.Type == ie.UpdateURR && isNullIE(duration) {
		urrInfo.TimeThreshold = 0
	}
	if urr.Type == ie.UpdateURR || method.HasVOLUM() {
		if threshold, err := volume.VolumeThreshold(); err == nil && threshold.HasTOVOL() {
			urrInfo.VolumeThreshold = threshold.TotalVolume
		}
	}
	if urr.Type == ie.UpdateURR || method.HasDURAT() {
		if threshold, err := duration.TimeThreshold(); err == nil {
			urrInfo.TimeThreshold = threshold.Seconds()
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
	if err := validateSessionRuleIDs(session, req.CreatePDR, req.CreateFAR, req.CreateQER, req.CreateURR); err != nil {
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

	return nil
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
		operationPool.Add(Operation{
			Apply: func(pdr SPDRInfo) func() error {
				return func() error {
					return pdrContext.deletePDR(pdr, mapOperations)
				}
			}(pdr),

			Rollback: func(pdr SPDRInfo) func() error {
				return func() error {
					applyPDR(pdr, mapOperations)

					return nil
				}
			}(pdr),
		})
	}

	for pfcpFarID, far := range session.FARs {
		operationPool.Add(Operation{
			Apply: func(far SFarInfo) func() error {
				return func() error {
					return mapOperations.DeleteFar(far.GlobalId)
				}
			}(far),

			Rollback: func(pfcpFarID uint32, far SFarInfo) func() error {
				return func() error {
					newInternalID, err := conn.mapOperations.NewFar(far.FarInfo)
					if err != nil {
						logger.Warn().Msgf("Can't put FAR: %s", err.Error())
						return err
					}

					session.NewFar(pfcpFarID, newInternalID, far.FarInfo)
					return nil
				}
			}(pfcpFarID, far),
		})
	}

	for pfcpQerID, qer := range session.QERs {
		operationPool.Add(Operation{
			Apply: func(qer SQerInfo) func() error {
				return func() error {
					return mapOperations.DeleteQer(qer.GlobalId)
				}
			}(qer),

			Rollback: func(pfcpQerID uint32, qer SQerInfo) func() error {
				return func() error {
					newInternalID, err := conn.mapOperations.NewQer(qer.QerInfo)
					if err != nil {
						logger.Warn().Msgf("Can't put QER: %s", err.Error())
						return err
					}

					session.NewQer(pfcpQerID, newInternalID, qer.QerInfo)
					return nil
				}
			}(pfcpQerID, qer),
		})
	}

	session.URRSequence += 1

	for urrID, urr := range session.URRs {
		operationPool.Add(Operation{
			Apply: func(urrID uint32, urr SUrrInfo) func() error {
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
						conn.profile.URSEQN(session.URRSequence, urr.ReportSeqNumber),
						ie.NewUsageReportTrigger(0, 1<<3, 0),
						ie.NewEndTime(time.Now()),
						ie.NewVolumeMeasurement(0x7, uplink+downlink, uplink, downlink, 0, 0, 0),
					}, conn.profile.UsageReportDeletionVendorIEs()...)
					report := ie.NewUsageReportWithinSessionDeletionResponse(deletionReportIEs...)

					*deletedURRs = append(*deletedURRs, report)

					return nil
				}
			}(urrID, urr),

			Rollback: func(urrID uint32, urr SUrrInfo) func() error {
				return func() error {
					newInternalID, err := mapOperations.NewUrr(urr.UrrInfo)
					if err != nil {
						return err
					}

					session.URRs[urrID] = SUrrInfo{
						UrrInfo:         urr.UrrInfo,
						GlobalId:        newInternalID,
						ReportSeqNumber: urr.ReportSeqNumber,
					}

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
	removedURRs *[]*ie.IE,
	session *Session,
) error {
	if err := validateSessionRuleIDs(session, req.CreatePDR, req.UpdatePDR, req.RemovePDR,
		req.CreateFAR, req.UpdateFAR, req.RemoveFAR, req.CreateQER, req.UpdateQER, req.RemoveQER,
		req.CreateURR, req.UpdateURR, req.RemoveURR); err != nil {
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
	err = updatePDRs(req.UpdatePDR, session, operationPool, logger, isTraced, conn, pdrContext)
	if err != nil {
		return err
	}
	err = removePDRs(req.RemovePDR, session, operationPool, logger, mapOperations, pdrContext)
	if err != nil {
		return err
	}

	return nil
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

		var created bool
		operationPool.Add(Operation{
			Apply: func() func() error {
				return func() error {
					id, err := mapOperations.NewFar(farInfo)
					if err != nil {
						logger.Warn().Msgf("Can't put FAR: %s", err.Error())
						return err
					}

					created = true

					session.NewFar(farID, id, farInfo)
					return nil
				}
			}(),

			Rollback: func() func() error {
				return func() error {
					if !created {
						return nil
					}

					far, err := session.RemoveFar(farID)
					if err != nil {
						return err
					}

					return mapOperations.DeleteFar(far.GlobalId)
				}
			}(),
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

		var created bool
		operationPool.Add(Operation{
			Apply: func() func() error {
				return func() error {
					id, err := mapOperations.NewQer(qerInfo)
					if err != nil {
						logger.Warn().Msgf("Can't put QER: %s", err.Error())
						return err
					}

					created = true

					session.NewQer(qerID, id, qerInfo)
					return nil
				}
			}(),

			Rollback: func() func() error {
				return func() error {
					if !created {
						return nil
					}

					qer, err := session.RemoveQer(qerID)
					if err != nil {
						return err
					}

					return mapOperations.DeleteQer(qer.GlobalId)
				}
			}(),
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

		var created bool
		operationPool.Add(Operation{
			Apply: func() func() error {
				return func() error {
					id, err := mapOperations.NewUrr(urrInfo)
					if err != nil {
						logger.Error().Msgf("Can't put URR: %s", err.Error())
						return err
					}

					created = true

					session.NewUrr(urrID, id, urrInfo)
					return nil
				}
			}(),

			Rollback: func() func() error {
				return func() error {
					if !created {
						return nil
					}

					urr, err := session.RemoveUrr(urrID)
					if err != nil {
						return err
					}

					_, err = mapOperations.DeleteUrr(urr.GlobalId)

					return err
				}
			}(),
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
	sdfFilters := make([]ebpf.SdfFilter, 0, len(PDRs))

	for _, pdr := range PDRs {
		fields, decodeErr := pdr.CreatePDR()
		if decodeErr != nil {
			return decodeErr
		}
		pdi, err := fields.PDI.PDI()
		if err != nil {
			continue
		}

		if ne, err := pdi.NetworkInstance.NetworkInstance(); err == nil && !conn.ValidateNetworkInstance(ne) {
			return errNotAllowedNetworkInstance
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

		stored := false
		operationPool.Add(Operation{
			Apply: func() func() error {
				return func() error {
					if err := pdrContext.extractPDR(pdrCopy, &spdrInfo); err != nil {
						return &ruleFailure{ie.RuleIDTypePDR, uint32(pdrID), err}
					}
					if spdrInfo.PCCInfo != nil {
						rule, ok := conn.PCCRules[spdrInfo.PCCInfo.PCCName]
						if !ok {
							logger.Warn().
								Str("pcc rule name", spdrInfo.PCCInfo.PCCName).
								Uint16("pdrID", pdrID).
								Msgf("PCC rule not found. PDR not created")

							return &ruleFailure{ie.RuleIDTypePDR, uint32(pdrID), fmt.Errorf("predefined rule %q is not configured", spdrInfo.PCCInfo.PCCName)}
						}

						spdrInfo.PCCInfo = &rule
						sdfFilters = append(sdfFilters, spdrInfo.PCCInfo.SDFFilter)
						logger.Debug().
							Str("pcc rule name", spdrInfo.PCCInfo.PCCName).
							Uint16("pdrID", pdrID).
							Msgf("PCC rule found: %+v", spdrInfo.PCCInfo)
					}

					logger.Debug().Msgf("pdr: %+v", spdrInfo)
					session.PutPDR(spdrInfo.PdrID, spdrInfo)
					stored = true
					applyPDR(spdrInfo, mapOperations)
					*createdPDRs = append(*createdPDRs, spdrInfo)
					return nil
				}
			}(),

			Rollback: func() func() error {
				return func() error {
					if !stored {
						return nil
					}
					if _, err := session.RemovePDR(spdrInfo.PdrID); err != nil {
						return err
					}

					return pdrContext.deletePDR(spdrInfo, mapOperations)
				}
			}(),
		})
	}

	applySdfFiltersToSession(session, sdfFilters, mapOperations)

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

		operationPool.Add(Operation{
			Apply: func() func() error {
				return func() error {
					session.UpdateFar(farID, newFar.FarInfo)
					return mapOperations.UpdateFar(newFar.GlobalId, newFar.FarInfo)
				}
			}(),

			Rollback: func() func() error {
				return func() error {
					session.UpdateFar(farID, oldFar.FarInfo)
					return mapOperations.UpdateFar(oldFar.GlobalId, oldFar.FarInfo)
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

		operationPool.Add(Operation{
			Apply: func() func() error {
				return func() error {
					session.UpdateQer(qerID, newQer.QerInfo)
					return mapOperations.UpdateQer(newQer.GlobalId, newQer.QerInfo)
				}
			}(),

			Rollback: func() func() error {
				return func() error {
					session.UpdateQer(qerID, oldQer.QerInfo)
					return mapOperations.UpdateQer(oldQer.GlobalId, oldQer.QerInfo)
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

		operationPool.Add(Operation{
			Apply: func() func() error {
				return func() error {
					session.UpdateUrr(urrID, newUrr.UrrInfo)
					return mapOperations.UpdateUrr(newUrr.GlobalId, newUrr.UrrInfo)
				}
			}(),

			Rollback: func() func() error {
				return func() error {
					session.UpdateUrr(urrID, oldUrr.UrrInfo)
					return mapOperations.UpdateUrr(oldUrr.GlobalId, oldUrr.UrrInfo)
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
) error {
	mapOperations := conn.mapOperations

	delSDFFilters := make([]ebpf.SdfFilter, 0)
	sdfFilters := make([]ebpf.SdfFilter, 0, len(PDRs))

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

		operationPool.Add(Operation{
			Apply: func(pdr *ie.IE, pdrID uint32, oldInfo, newInfo *SPDRInfo) func() error {
				return func() error {
					if err := pdrContext.extractPDR(pdr, newInfo); err != nil {
						logger.Printf("Error extracting PDR info: %s", err.Error())

						return err
					}

					if newInfo.PCCInfo != nil && oldInfo.PCCInfo == nil {
						if err := pdrContext.deletePDR(*newInfo, mapOperations); err != nil {
							logger.Info().Msgf("Failed to remove uplink PDR: %v", err)
						}

						delSDFFilters = append(delSDFFilters, newInfo.PCCInfo.SDFFilter)

						return nil
					} else if newInfo.PCCInfo == nil && oldInfo.PCCInfo != nil {
						rule, ok := conn.PCCRules[oldInfo.PCCInfo.PCCName]
						if !ok {
							logger.Warn().
								Str("pcc rule name", oldInfo.PCCInfo.PCCName).
								Uint32("pdrID", pdrID).
								Msgf("PCC rule not found")

							return nil
						}

						oldInfo.PCCInfo = &rule
						sdfFilters = append(sdfFilters, oldInfo.PCCInfo.SDFFilter)
						logger.Debug().
							Str("pcc rule name", oldInfo.PCCInfo.PCCName).
							Uint32("pdrID", pdrID).
							Msgf("PCC rule found: %+v", oldInfo.PCCInfo)
					}

					if newInfo.PCCInfo != nil {
						return nil
					}

					session.PutPDR(pdrID, *newInfo)
					applyPDR(*newInfo, mapOperations)

					return nil
				}
			}(pdrCopy, uint32(pdrID), &oldInfo, &newInfo),

			Rollback: func(pdrID uint32, oldInfo *SPDRInfo, newInfo *SPDRInfo) func() error {
				return func() error {
					if oldInfo.PCCInfo != nil && newInfo.PCCInfo == nil {
						session.PutPDR(pdrID, *oldInfo)
						applyPDR(*oldInfo, mapOperations)
						return nil
					}

					session.PutPDR(pdrID, *oldInfo)
					applyPDR(*oldInfo, mapOperations)

					return nil
				}
			}(uint32(pdrID), &oldInfo, &newInfo),
		})
	}

	removeSdfFiltersFromSession(session, delSDFFilters, mapOperations)
	applySdfFiltersToSession(session, sdfFilters, mapOperations)

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

		operationPool.Add(Operation{
			Apply: func() error {
				return mapOperations.DeleteFar(oldFar.GlobalId)
			},
			Rollback: func() error {
				internalID, err := mapOperations.NewFar(oldFar.FarInfo)
				if err != nil {
					logger.Info().Msgf("Can't rollback FAR: %s", err.Error())
					return err
				}
				session.NewFar(farID, internalID, oldFar.FarInfo)
				return nil
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

		operationPool.Add(Operation{
			Apply: func() error {
				return mapOperations.DeleteQer(oldQer.GlobalId)
			},
			Rollback: func() error {
				internalID, err := mapOperations.NewQer(oldQer.QerInfo)
				if err != nil {
					return err
				}
				session.NewQer(qerID, internalID, oldQer.QerInfo)
				return nil
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

		operationPool.Add(Operation{
			Apply: func() error {
				newReport, err := mapOperations.DeleteUrr(oldUrr.GlobalId)
				if err != nil {
					return err
				}

				uplink := newReport.UplinkVolume - oldUrr.UrrInfo.UplinkVolume
				downlink := newReport.DownlinkVolume - oldUrr.UrrInfo.DownlinkVolume

				report := ie.NewUsageReportWithinSessionModificationResponse(
					ie.NewURRID(urrID),
					profile.URSEQN(session.URRSequence, oldUrr.ReportSeqNumber+1),
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
			Rollback: func() error {
				newGlobalID, err := mapOperations.NewUrr(oldUrr.UrrInfo)
				if err != nil {
					return err
				}

				session.URRs[urrID] = SUrrInfo{
					UrrInfo:         oldUrr.UrrInfo,
					GlobalId:        newGlobalID,
					ReportSeqNumber: oldUrr.ReportSeqNumber,
				}
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

		operationPool.Add(Operation{
			Apply: func() error {
				return pdrContext.deletePDR(oldPdr, mapOperations)
			},
			Rollback: func() error {
				session.PutPDR(pdrKey, oldPdr)
				applyPDR(oldPdr, mapOperations)
				return nil
			},
		})
	}

	return nil
}
