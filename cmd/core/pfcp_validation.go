package core

import (
	"errors"
	"fmt"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type requestIEError struct {
	cause     uint8
	offending ie.IEType
	err       error
}

func (e *requestIEError) Error() string { return fmt.Sprintf("PFCP IE %d: %v", e.offending, e.err) }
func (e *requestIEError) Unwrap() error { return e.err }

func invalidRequestIE(typ ie.IEType, err error) *requestIEError {
	cause := ie.CauseMandatoryIEIncorrect
	// TS 29.244 V20.1.0 clauses 7.6.7 and 7.6.8 distinguish framing from invalid values.
	var decode *ie.DecodeError
	if errors.As(err, &decode) {
		if errors.Is(err, ie.ErrInvalidLength) {
			cause = ie.CauseInvalidLength
		}
		if !decode.TypeUnknown {
			typ = decode.Type
		}
	}
	return &requestIEError{cause, typ, err}
}

type requiredIE struct {
	typ   ie.IEType
	value *ie.IE
}

func requireIEs(fields ...requiredIE) *requestIEError {
	for _, field := range fields {
		// TS 29.244 V20.1.0 clause 7.6.6: presence is distinct from a malformed value.
		if field.value == nil {
			return &requestIEError{ie.CauseMandatoryIEMissing, field.typ, ie.ErrIENotFound}
		}
		var err error
		switch field.typ {
		case ie.NodeID:
			_, err = field.value.NodeID()
		case ie.RecoveryTimeStamp:
			_, err = field.value.RecoveryTimeStamp()
		case ie.FSEID:
			_, err = field.value.FSEID()
		case ie.PDRID:
			_, err = field.value.PDRID()
		case ie.Precedence:
			_, err = field.value.Precedence()
		case ie.SourceInterface:
			_, err = field.value.SourceInterface()
		case ie.DestinationInterface:
			_, err = field.value.DestinationInterface()
		case ie.FARID:
			_, err = field.value.FARID()
		case ie.QERID:
			_, err = field.value.QERID()
		case ie.URRID:
			_, err = field.value.URRID()
		case ie.BARID:
			_, err = field.value.BARID()
		case ie.ApplyAction:
			err = field.value.ValidateApplyAction()
		case ie.GateStatus:
			_, err = field.value.GateStatus()
		case ie.MeasurementMethod:
			_, err = field.value.MeasurementMethod()
		case ie.ReportingTriggers:
			_, err = field.value.ReportingTriggers()
		}
		if err != nil {
			return invalidRequestIE(field.typ, err)
		}
	}
	return nil
}

func validatePDI(value *ie.IE, required bool) *requestIEError {
	if value == nil {
		if required {
			return &requestIEError{ie.CauseMandatoryIEMissing, ie.PDI, ie.ErrIENotFound}
		}
		return nil
	}
	children, err := value.ValueAsGrouped()
	if err != nil {
		return invalidRequestIE(ie.PDI, err)
	}
	// TS 29.244 V20.1.0 Tables 7.5.2.2-1 and 7.5.2.2-2.
	return requireIEs(requiredIE{ie.SourceInterface, firstChild(children, ie.SourceInterface)})
}

// firstChild follows the codec's first-occurrence rule (clause 7.6.10).
// Mandatory-presence checks need only these children, rather than allocating
// complete typed views that the rule planner will construct afterwards.
func firstChild(children []*ie.IE, typ ie.IEType) *ie.IE {
	for _, child := range children {
		if child != nil && child.Type == typ {
			return child
		}
	}
	return nil
}

// validateRule checks mandatory children of the rule families consumed by this UPF.
// TS 29.244 V20.1.0 clauses 7.5.2.2-7.5.2.6 and 7.5.4.2-7.5.4.13.
func validateRule(value *ie.IE) *requestIEError {
	switch value.Type {
	case ie.CreatePDR:
		children, err := value.ValueAsGrouped()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		if failure := requireIEs(requiredIE{ie.PDRID, firstChild(children, ie.PDRID)}, requiredIE{ie.Precedence, firstChild(children, ie.Precedence)}); failure != nil {
			return failure
		}
		return validatePDI(firstChild(children, ie.PDI), true)
	case ie.UpdatePDR:
		f, err := value.UpdatePDR()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		if failure := requireIEs(requiredIE{ie.PDRID, f.PDRID}); failure != nil {
			return failure
		}
		return validatePDI(f.PDI, false)
	case ie.RemovePDR:
		f, err := value.RemovePDR()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.PDRID, f.PDRID})
	case ie.CreateFAR:
		children, err := value.ValueAsGrouped()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		action := firstChild(children, ie.ApplyAction)
		if failure := requireIEs(requiredIE{ie.FARID, firstChild(children, ie.FARID)}, requiredIE{ie.ApplyAction, action}); failure != nil {
			return failure
		}
		forwarding := firstChild(children, ie.ForwardingParameters)
		// TS 29.244 V20.1.0 Table 7.5.2.3-1: FORW makes Forwarding Parameters conditional-mandatory.
		if action.HasFORW() && forwarding == nil {
			return &requestIEError{ie.CauseConditionalIEMissing, ie.ForwardingParameters, ie.ErrIENotFound}
		}
		if forwarding != nil {
			forward, err := forwarding.ValueAsGrouped()
			if err != nil {
				return invalidRequestIE(ie.ForwardingParameters, err)
			}
			return requireIEs(requiredIE{ie.DestinationInterface, firstChild(forward, ie.DestinationInterface)})
		}
	case ie.UpdateFAR:
		children, err := value.ValueAsGrouped()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.FARID, firstChild(children, ie.FARID)})
	case ie.RemoveFAR:
		f, err := value.RemoveFAR()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.FARID, f.FARID})
	case ie.CreateBAR:
		f, err := value.CreateBAR()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.BARID, f.BARID})
	case ie.UpdateBARWithinSessionModificationRequest:
		f, err := value.UpdateBARWithinSessionModificationRequest()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.BARID, f.BARID})
	case ie.RemoveBAR:
		f, err := value.RemoveBAR()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.BARID, f.BARID})
	case ie.CreateQER:
		f, err := value.CreateQER()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.QERID, f.QERID}, requiredIE{ie.GateStatus, f.GateStatus})
	case ie.UpdateQER:
		f, err := value.UpdateQER()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.QERID, f.QERID})
	case ie.RemoveQER:
		f, err := value.RemoveQER()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.QERID, f.QERID})
	case ie.CreateURR:
		f, err := value.CreateURR()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.URRID, f.URRID}, requiredIE{ie.MeasurementMethod, f.MeasurementMethod}, requiredIE{ie.ReportingTriggers, f.ReportingTriggers})
	case ie.UpdateURR:
		f, err := value.UpdateURR()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.URRID, f.URRID})
	case ie.RemoveURR:
		f, err := value.RemoveURR()
		if err != nil {
			return invalidRequestIE(value.Type, err)
		}
		return requireIEs(requiredIE{ie.URRID, f.URRID})
	}
	return nil
}

func validateIncomingRequest(msg message.Message) *requestIEError {
	var lists [][]*ie.IE
	switch request := msg.(type) {
	case *message.AssociationSetupRequest:
		return requireIEs(requiredIE{ie.NodeID, request.NodeID}, requiredIE{ie.RecoveryTimeStamp, request.RecoveryTimeStamp})
	case *message.AssociationUpdateRequest:
		return requireIEs(requiredIE{ie.NodeID, request.NodeID})
	case *message.AssociationReleaseRequest:
		return requireIEs(requiredIE{ie.NodeID, request.NodeID})
	case *message.SessionEstablishmentRequest:
		// TS 29.244 V20.1.0 Table 7.5.2.1-1.
		if failure := requireIEs(requiredIE{ie.NodeID, request.NodeID}, requiredIE{ie.FSEID, request.CPFSEID}); failure != nil {
			return failure
		}
		if len(request.CreatePDR) == 0 {
			return &requestIEError{ie.CauseMandatoryIEMissing, ie.CreatePDR, ie.ErrIENotFound}
		}
		if len(request.CreateFAR) == 0 {
			return &requestIEError{ie.CauseMandatoryIEMissing, ie.CreateFAR, ie.ErrIENotFound}
		}
		lists = [][]*ie.IE{request.CreatePDR, request.CreateFAR, request.CreateQER, request.CreateURR, {request.CreateBAR}}
	case *message.SessionModificationRequest:
		lists = [][]*ie.IE{request.CreatePDR, request.UpdatePDR, request.RemovePDR, request.CreateFAR, request.UpdateFAR, request.RemoveFAR, request.CreateQER, request.UpdateQER, request.RemoveQER, request.CreateURR, request.UpdateURR, request.RemoveURR, {request.CreateBAR, request.UpdateBAR, request.RemoveBAR}}
	}
	for _, list := range lists {
		for _, value := range list {
			if value == nil {
				continue
			}
			if failure := validateRule(value); failure != nil {
				return failure
			}
		}
	}
	return nil
}

// errorResponse includes the mandatory response fields even when rejecting a request.
// TS 29.244 V20.1.0 clause 7.2.3.2, Tables 7.4.4.2/4/6-1 and clauses 7.5.3/5/7.
func (conn *PfcpConnection) errorResponse(responseType uint8, seid uint64, seq uint32, cause uint8, offending *ie.IE) message.Message {
	node := conn.profile.NodeID(conn.nodeId)
	switch responseType {
	case message.MsgTypeAssociationSetupResponse:
		return message.NewAssociationSetupResponse(seq, node, ie.NewCause(cause), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), offending)
	case message.MsgTypeAssociationUpdateResponse:
		return message.NewAssociationUpdateResponse(seq, node, ie.NewCause(cause), offending)
	case message.MsgTypeAssociationReleaseResponse:
		return message.NewAssociationReleaseResponse(seq, node, ie.NewCause(cause), offending)
	case message.MsgTypeSessionEstablishmentResponse:
		return message.NewSessionEstablishmentResponse(seid, seq, node, ie.NewCause(cause), offending)
	case message.MsgTypeSessionModificationResponse:
		return message.NewSessionModificationResponse(seid, seq, ie.NewCause(cause), offending)
	case message.MsgTypeSessionDeletionResponse:
		return message.NewSessionDeletionResponse(seid, seq, ie.NewCause(cause), offending)
	}
	return nil
}

func (conn *PfcpConnection) peerSEID(request message.Message, addr string) uint64 {
	if request, ok := request.(*message.SessionEstablishmentRequest); ok {
		if fields, err := request.CPFSEID.FSEID(); err == nil {
			return fields.SEID
		}
		return 0
	}
	// TS 29.244 V20.1.0 clauses 7.2.2.4.1 and 7.2.2.4.2: the response uses the peer's SEID.
	return conn.peerSessionSEID(request.SEID(), addr)
}

func (conn *PfcpConnection) peerSessionSEID(localSEID uint64, addr string) uint64 {
	if association := conn.GetAssociation(addr); association != nil {
		if session := association.Sessions[localSEID]; session != nil {
			return session.RemoteSEID
		}
	}
	return 0
}
