package core

import (
	"fmt"
	"reflect"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func unsupportedRuleIE(typ ie.IEType) error {
	return &requestIEError{ie.CauseServiceNotSupported, typ, fmt.Errorf("%s: %w", typ, ebpf.ErrUnsupportedRuleContent)}
}

// rejectUnsupportedFields audits the codec's complete typed view, including
// newly added standard fields. OtherIEs remain ignored under clauses 7.6.9 and
// 7.6.10; they contain unknown/unexpected types and extra singular occurrences.
func rejectUnsupportedFields(fields interface{}, supported ...string) error {
	value := reflect.ValueOf(fields).Elem()
	allowed := map[string]bool{"OtherIEs": true}
	for _, name := range supported {
		allowed[name] = true
	}
	for field := range value.Type().Fields() {
		if allowed[field.Name] {
			continue
		}
		entry := value.FieldByIndex(field.Index)
		switch child := entry.Interface().(type) {
		case *ie.IE:
			if child != nil {
				return unsupportedRuleIE(child.Type)
			}
		case []*ie.IE:
			if len(child) > 0 {
				return unsupportedRuleIE(child[0].Type)
			}
		}
	}
	return nil
}
func validateRuleCapability(rule *ie.IE) error {
	switch rule.Type {
	case ie.CreatePDR:
		f, err := rule.CreatePDR()
		if err != nil {
			return err
		}
		if err := rejectUnsupportedFields(f, "PDRID", "Precedence", "PDI", "OuterHeaderRemoval", "FARID", "QERID", "URRID", "ActivatePredefinedRules"); err != nil {
			return err
		}
		if err := validateOuterRemoval(f.OuterHeaderRemoval); err != nil {
			return err
		}
		if err := validateBindingBounds(f.QERID, f.URRID); err != nil {
			return err
		}
		return validatePDICapability(f.PDI)
	case ie.UpdatePDR:
		f, err := rule.UpdatePDR()
		if err != nil {
			return err
		}
		if err := rejectUnsupportedFields(f, "PDRID", "Precedence", "PDI", "OuterHeaderRemoval", "FARID", "QERID", "URRID"); err != nil {
			return err
		}
		if err := validateOuterRemoval(f.OuterHeaderRemoval); err != nil {
			return err
		}
		if err := validateBindingBounds(f.QERID, f.URRID); err != nil {
			return err
		}
		return validatePDICapability(f.PDI)
	case ie.CreateFAR:
		f, err := rule.CreateFAR()
		if err != nil {
			return err
		}
		if err := rejectUnsupportedFields(f, "FARID", "ApplyAction", "ForwardingParameters"); err != nil {
			return err
		}
		if err := validateSupportedAction(f.ApplyAction); err != nil {
			return err
		}
		if f.ForwardingParameters != nil {
			v, err := f.ForwardingParameters.ForwardingParameters()
			if err != nil {
				return err
			}
			return validateForwardingCapability(v, v.DestinationInterface, v.ForwardingPolicy)
		}
	case ie.UpdateFAR:
		f, err := rule.UpdateFAR()
		if err != nil {
			return err
		}
		if err := rejectUnsupportedFields(f, "FARID", "ApplyAction", "UpdateForwardingParameters"); err != nil {
			return err
		}
		if err := validateSupportedAction(f.ApplyAction); err != nil {
			return err
		}
		if f.UpdateForwardingParameters != nil {
			v, err := f.UpdateForwardingParameters.UpdateForwardingParameters()
			if err != nil {
				return err
			}
			return validateForwardingCapability(v, v.DestinationInterface, v.ForwardingPolicy)
		}
	case ie.CreateQER:
		f, err := rule.CreateQER()
		if err != nil {
			return err
		}
		if err := rejectUnsupportedFields(f, "QERID", "GateStatus", "MaximumBitrate", "QoSFlowIdentifier", "ReflectiveQoS"); err != nil {
			return err
		}
		return validateGate(f.GateStatus)
	case ie.UpdateQER:
		f, err := rule.UpdateQER()
		if err != nil {
			return err
		}
		if err := rejectUnsupportedFields(f, "QERID", "GateStatus", "MaximumBitrate", "QoSFlowIdentifier", "ReflectiveQoS"); err != nil {
			return err
		}
		return validateGate(f.GateStatus)
	case ie.CreateURR:
		f, err := rule.CreateURR()
		if err != nil {
			return err
		}
		if err := rejectUnsupportedFields(f, "URRID", "MeasurementMethod", "ReportingTriggers", "VolumeThreshold"); err != nil {
			return err
		}
		return validateURRSubset(f.MeasurementMethod, f.ReportingTriggers, f.VolumeThreshold, true)
	case ie.UpdateURR:
		f, err := rule.UpdateURR()
		if err != nil {
			return err
		}
		// Null unsupported optional fields may remove a previously provisioned
		// value; they request no unsupported runtime functionality (5.6.3).
		if isNullIE(f.TimeThreshold) {
			f.TimeThreshold = nil
		}
		if err := rejectUnsupportedFields(f, "URRID", "MeasurementMethod", "ReportingTriggers", "VolumeThreshold"); err != nil {
			return err
		}
		return validateURRSubset(f.MeasurementMethod, f.ReportingTriggers, f.VolumeThreshold, false)
	}
	return nil
}
func validateBindingBounds(qers, urrs []*ie.IE) error {
	null := func(list []*ie.IE) bool {
		for _, i := range list {
			if isNullIE(i) {
				return true
			}
		}
		return false
	}
	if len(qers) > ebpf.MaxQERsPerPDR && !null(qers) || len(urrs) > ebpf.MaxURRsPerPDR && !null(urrs) {
		return ebpf.ErrRuleCapacity
	}
	return nil
}
func validatePDICapability(pdi *ie.IE) error {
	if pdi == nil {
		return nil
	}
	f, err := pdi.PDI()
	if err != nil {
		return err
	}
	if err := rejectUnsupportedFields(f, "SourceInterface", "LocalFTEID", "NetworkInstance", "UEIPAddress", "SDFFilter", "QFI"); err != nil {
		return err
	}
	if len(f.QFI) > ebpf.MaxQFIsPerPDR {
		return ebpf.ErrRuleCapacity
	}
	if len(f.UEIPAddress) > 1 {
		return unsupportedRuleIE(ie.UEIPAddress)
	}
	if f.SourceInterface != nil {
		source, err := f.SourceInterface.SourceInterface()
		if err != nil {
			return err
		}
		if source != ie.SrcInterfaceAccess && source != ie.SrcInterfaceCore {
			return unsupportedRuleIE(ie.SourceInterface)
		}
	}
	for _, field := range f.UEIPAddress {
		ip, err := field.UEIPAddress()
		if err != nil {
			return err
		}
		if ip.Flags&32 != 0 {
			return unsupportedRuleIE(ie.UEIPAddress)
		}
	}
	for _, field := range f.SDFFilter {
		filter, err := field.SDFFilter()
		if err != nil {
			return err
		}
		// Only Flow Description is implemented; ToS/TC, SPI, Flow Label,
		// bidirectional filters and their identifiers are not tuple matches.
		if filter.Flags&uint8(0x3e) != 0 {
			return unsupportedRuleIE(ie.SDFFilter)
		}
	}
	return nil
}
func validateSupportedAction(action *ie.IE) error {
	if action == nil || isNullIE(action) {
		return nil
	}
	flags, err := action.ApplyAction()
	if err != nil {
		return err
	}
	if flags[0]&^uint8(3) != 0 {
		return unsupportedRuleIE(ie.ApplyAction)
	}
	if len(flags) > 1 && flags[1]&0x1f != 0 {
		return unsupportedRuleIE(ie.ApplyAction)
	}
	return nil
}
func validateForwardingCapability(fields interface{}, destination, policy *ie.IE) error {
	if policy != nil {
		return &requestIEError{ie.CauseInvalidForwardingPolicy, ie.ForwardingPolicy, fmt.Errorf("no forwarding policy is configured")}
	}
	if err := rejectUnsupportedFields(fields, "DestinationInterface", "NetworkInstance", "OuterHeaderCreation", "TransportLevelMarking"); err != nil {
		return err
	}
	if destination != nil {
		value, err := destination.DestinationInterface()
		if err != nil {
			return err
		}
		if value > 2 {
			return unsupportedRuleIE(ie.DestinationInterface)
		}
	}
	return nil
}
func validateGate(gate *ie.IE) error {
	if gate == nil || isNullIE(gate) {
		return nil
	}
	ul, err := gate.GateStatusUL()
	if err != nil {
		return err
	}
	dl, err := gate.GateStatusDL()
	if err != nil {
		return err
	}
	if ul > 1 || dl > 1 {
		return invalidRequestIE(ie.GateStatus, fmt.Errorf("reserved gate status"))
	}
	return nil
}

// TS 29.244 V20.1.0 clauses 5.2.2.2.1 and 5.2.2.3.1: the supported
// subset measures post-QoS octets, a positive total-volume threshold and final
// reports. No duration/event/packet/quota/periodic/linked measurement is claimed.
func validateURRSubset(method, triggers, volume *ie.IE, create bool) error {
	if method != nil {
		value, err := method.MeasurementMethod()
		if err != nil {
			return err
		}
		if value&7 == 0 {
			return invalidRequestIE(ie.MeasurementMethod, fmt.Errorf("empty measurement method"))
		}
		if value&7 != 2 {
			return unsupportedRuleIE(ie.MeasurementMethod)
		}
	}
	if triggers != nil && !isNullIE(triggers) {
		flags, err := triggers.ReportingTriggers()
		if err != nil {
			return err
		}
		if flags[0]&^uint8(2) != 0 {
			return unsupportedRuleIE(ie.ReportingTriggers)
		}
		if len(flags) > 1 && flags[1] != 0 || len(flags) > 2 && flags[2]&3 != 0 {
			return unsupportedRuleIE(ie.ReportingTriggers)
		}
		// Clause 8.2.19 requires a named trigger; spare bits are discarded.
		if flags[0]&2 == 0 {
			return invalidRequestIE(ie.ReportingTriggers, fmt.Errorf("empty reporting triggers"))
		}
		if triggers.HasVOLTH() && volume == nil && create {
			return &requestIEError{ie.CauseConditionalIEMissing, ie.VolumeThreshold, ie.ErrIENotFound}
		}
	}
	if volume != nil && !isNullIE(volume) {
		value, err := volume.VolumeThreshold()
		if err != nil {
			return err
		}
		if value.Flags != 1 || value.TotalVolume == 0 {
			return unsupportedRuleIE(ie.VolumeThreshold)
		}
	}
	return nil
}

// validateSessionCapability rejects requested procedures without a runtime
// implementation. Descriptive subscriber/network metadata does not request one.
// TS 29.244 V20.1.0 clause 7.5 and Table 8.2.1-1 (Service not supported).
func validateSessionCapability(request interface{}) error {
	switch r := request.(type) {
	case *message.SessionEstablishmentRequest:
		if err := rejectUnsupportedFields(r, "NodeID", "CPFSEID", "CreatePDR", "CreateFAR", "CreateQER", "CreateURR", "PDNType", "FQCSID", "UserID", "TraceInformation", "APNDNN", "SNSSAI", "HPLMNSNSSAI", "RATType", "RecoveryTimeStamp", "PFCPSEReqFlags"); err != nil {
			return err
		}
		if r.PFCPSEReqFlags != nil {
			flags, err := r.PFCPSEReqFlags.PFCPSEReqFlags()
			if err != nil {
				return err
			}
			if flags&uint8(0x0e) != 0 {
				return unsupportedRuleIE(ie.PFCPSEReqFlags)
			}
		}
	case *message.SessionModificationRequest:
		return rejectUnsupportedFields(r, "NodeID", "CPFSEID", "CreatePDR", "UpdatePDR", "RemovePDR", "CreateFAR", "UpdateFAR", "RemoveFAR", "CreateQER", "UpdateQER", "RemoveQER", "CreateURR", "UpdateURR", "RemoveURR", "FQCSID", "UserID", "TraceInformation", "APNDNN", "SNSSAI", "HPLMNSNSSAI", "RATType")
	}
	return nil
}

func validateOuterRemoval(field *ie.IE) error {
	if field == nil || isNullIE(field) {
		return nil
	}
	value, err := field.OuterHeaderRemovalDescription()
	if err != nil {
		return err
	}
	if value != 0 && value != 6 {
		return unsupportedRuleIE(ie.OuterHeaderRemoval)
	}
	return nil
}

// validateSessionRuleShapes checks the final draft, so changing a FAR also
// validates every unchanged PDR that still references it. These are supported
// forwarding forms, not approximations of a more general PDI.
func validateSessionRuleShapes(conn *PfcpConnection, session *Session) error {
	for id, urr := range session.URRs {
		if urr.UrrInfo.VolumeTrigger && urr.UrrInfo.VolumeThreshold == 0 {
			return &ruleFailure{ie.RuleIDTypeURR, id, &requestIEError{ie.CauseConditionalIEMissing, ie.VolumeThreshold, ie.ErrIENotFound}}
		}
	}

	for id, pdr := range session.PDRs {
		var err error
		if pdr.Teid != 0 && pdr.PdrInfo.SourceInterfacePresent && pdr.SourceInterface == ie.SrcInterfaceCore && conn.n3Address.Equal(conn.n9Address) {
			err = unsupportedRuleIE(ie.SourceInterface)
		}
		if pdr.Teid == 0 && pdr.PdrInfo.SourceInterfacePresent {
			if pdr.SourceInterface != ie.SrcInterfaceCore {
				err = unsupportedRuleIE(ie.SourceInterface)
			}
			if !pdr.PdrInfo.UEDestination {
				err = unsupportedRuleIE(ie.UEIPAddress)
			}
			if pdr.PdrInfo.OuterHeaderRemovalPresent {
				err = unsupportedRuleIE(ie.OuterHeaderRemoval)
			}
		}
		if pdr.FARID != nil {
			far := session.FARs[*pdr.FARID].FarInfo
			if far.Action&2 != 0 {
				if pdr.Teid == 0 && far.OuterHeaderCreation != 1 {
					err = fmt.Errorf("native N6 forwarding requires a GTP-U return tunnel: %w", ebpf.ErrUnsupportedRuleContent)
				}
				if pdr.Teid != 0 && !pdr.PdrInfo.OuterHeaderRemovalPresent {
					err = unsupportedRuleIE(ie.OuterHeaderRemoval)
				}
			}
		}
		if err != nil {
			return &ruleFailure{ie.RuleIDTypePDR, id, err}
		}
	}
	return nil
}
