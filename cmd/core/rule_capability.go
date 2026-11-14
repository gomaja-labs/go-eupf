package core

import (
	"fmt"
	"reflect"
	"slices"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func unsupportedRuleIE(typ ie.IEType) error {
	return &requestIEError{ie.CauseServiceNotSupported, typ, fmt.Errorf("%s: %w", typ, ebpf.ErrUnsupportedRuleContent)}
}

// Informative fields admitted below are documented, IE by IE, in
// docs/rule-capabilities.md. Interface Type labels and RAT statistics metadata
// do not replace the Source/Destination Interface or request packet handling.
// rejectUnsupportedFields audits the codec's complete typed view, including
// newly added standard fields. OtherIEs remain ignored under clauses 7.6.9 and
// 7.6.10; they contain unknown/unexpected types and extra singular occurrences.
// capabilityFieldPlans holds immutable metadata for the finite set of codec
// views used below. Wire input cannot introduce a new Go type or field policy.
// A different policy for an existing type is inspected independently.
var capabilityFieldPlans sync.Map // reflect.Type -> *capabilityFieldPlan

type capabilityFieldPlan struct {
	supported []string
	fields    []int
}

func capabilityFields(typ reflect.Type, supported []string) *capabilityFieldPlan {
	if cached, ok := capabilityFieldPlans.Load(typ); ok {
		plan := cached.(*capabilityFieldPlan)
		if slices.Equal(plan.supported, supported) {
			return plan
		}
	}
	allowed := map[string]bool{"OtherIEs": true}
	for _, name := range supported {
		allowed[name] = true
	}
	plan := &capabilityFieldPlan{supported: slices.Clone(supported)}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if allowed[field.Name] {
			continue
		}
		if field.Type == reflect.TypeFor[*ie.IE]() || field.Type == reflect.TypeFor[[]*ie.IE]() {
			plan.fields = append(plan.fields, index)
		}
	}
	capabilityFieldPlans.LoadOrStore(typ, plan)
	return plan
}
func rejectUnsupportedFields(fields interface{}, supported ...string) error {
	value := reflect.ValueOf(fields).Elem()
	for _, index := range capabilityFields(value.Type(), supported).fields {
		switch child := value.Field(index).Interface().(type) {
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
		if err := rejectUnsupportedFields(f, "PDRID", "Precedence", "PDI", "OuterHeaderRemoval", "FARID", "QERID", "URRID", "ActivatePredefinedRules", "RATType"); err != nil {
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
		if err := rejectUnsupportedFields(f, "PDRID", "Precedence", "PDI", "OuterHeaderRemoval", "FARID", "QERID", "URRID", "RATType"); err != nil {
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
		if err := rejectUnsupportedFields(f, "FARID", "ApplyAction", "ForwardingParameters", "BARID"); err != nil {
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
		if err := rejectUnsupportedFields(f, "FARID", "ApplyAction", "UpdateForwardingParameters", "BARID"); err != nil {
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
			if v.PFCPSMReqFlags != nil {
				flags, err := v.PFCPSMReqFlags.PFCPSMReqFlags()
				if err != nil {
					return err
				}
				// TS 29.244 V20.1.0 clauses 8.2.31 and 7.5.4.3:
				// only SNDEM applies inside Update Forwarding Parameters.
				if flags&0x7d != 0 {
					return unsupportedRuleIE(ie.PFCPSMReqFlags)
				}
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
		if err := rejectUnsupportedFields(f, "URRID", "MeasurementMethod", "ReportingTriggers", "VolumeThreshold", "MeasurementInformation"); err != nil {
			return err
		}
		if err := validateMeasurementInformation(f.MeasurementInformation); err != nil {
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
		if err := rejectUnsupportedFields(f, "URRID", "MeasurementMethod", "ReportingTriggers", "VolumeThreshold", "MeasurementInformation"); err != nil {
			return err
		}
		if err := validateMeasurementInformation(f.MeasurementInformation); err != nil {
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
	if err := rejectUnsupportedFields(f, "SourceInterface", "LocalFTEID", "NetworkInstance", "UEIPAddress", "SDFFilter", "QFI", "SourceInterfaceType", "ProtocolDescription"); err != nil {
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
		if source != ie.SrcInterfaceAccess && source != ie.SrcInterfaceCore && source != ie.SrcInterfaceCPFunction {
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
	if flags[0]&^uint8(15) != 0 {
		return unsupportedRuleIE(ie.ApplyAction)
	}
	// TS 29.244 V20.1.0 clause 8.2.26: exactly one base action;
	// NOCP can accompany only BUFF. Unsupported actions remain rejected above.
	base := flags[0] & 7
	if base == 0 || base&(base-1) != 0 || flags[0]&8 != 0 && base != 4 {
		return invalidRequestIE(ie.ApplyAction, ie.ErrInvalidValue)
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
	if err := rejectUnsupportedFields(fields, "DestinationInterface", "NetworkInstance", "OuterHeaderCreation", "TransportLevelMarking", "DestinationInterfaceType", "DataNetworkAccessIdentifier", "PFCPSMReqFlags"); err != nil {
		return err
	}
	if destination != nil {
		value, err := destination.DestinationInterface()
		if err != nil {
			return err
		}
		// TS 29.244 V20.1.0 clause 5.3.1: N4-u/Sx-u uses GTP-U
		// forwarding with CP-function Source/Destination Interface values.
		if value > ie.DstInterfaceCPFunction {
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
		if err := rejectUnsupportedFields(r, "NodeID", "CPFSEID", "CreatePDR", "CreateFAR", "CreateQER", "CreateURR", "CreateBAR", "PDNType", "FQCSID", "UserID", "TraceInformation", "APNDNN", "SNSSAI", "HPLMNSNSSAI", "RATType", "RecoveryTimeStamp", "PFCPSEReqFlags"); err != nil {
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
		return rejectUnsupportedFields(r, "NodeID", "CPFSEID", "CreatePDR", "UpdatePDR", "RemovePDR", "CreateFAR", "UpdateFAR", "RemoveFAR", "CreateQER", "UpdateQER", "RemoveQER", "CreateURR", "UpdateURR", "RemoveURR", "CreateBAR", "UpdateBAR", "RemoveBAR", "FQCSID", "UserID", "TraceInformation", "APNDNN", "SNSSAI", "HPLMNSNSSAI", "RATType")
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
	// TS 29.244 V20.1.0 table 8.2.64-1 NOTE 7: unknown
	// descriptions are incorrect, rather than assigned unsupported formats.
	if value >= 9 {
		return &requestIEError{ie.CauseMandatoryIEIncorrect, ie.OuterHeaderRemoval, ie.ErrInvalidValue}
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
	if err := validateBARReferences(session); err != nil {
		return err
	}
	for id, urr := range session.URRs {
		if urr.UrrInfo.VolumeTrigger && urr.UrrInfo.VolumeThreshold == 0 {
			return &ruleFailure{ie.RuleIDTypeURR, id, &requestIEError{ie.CauseConditionalIEMissing, ie.VolumeThreshold, ie.ErrIENotFound}}
		}
	}

	// TS 29.244 V20.1.0 clause 5.3.1: the uniquely allocated N4-u TEID
	// identifies CP ingress. It cannot also identify a different source side.
	sources := make(map[uint32]uint8)
	for id, pdr := range session.PDRs {
		if pdr.Teid == 0 || !pdr.PdrInfo.SourceInterfacePresent {
			continue
		}
		previous, exists := sources[pdr.Teid]
		if exists && previous != pdr.SourceInterface && (previous == ie.SrcInterfaceCPFunction || pdr.SourceInterface == ie.SrcInterfaceCPFunction) {
			return &ruleFailure{ie.RuleIDTypePDR, id, unsupportedRuleIE(ie.SourceInterface)}
		}
		sources[pdr.Teid] = pdr.SourceInterface
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
				if pdr.SourceInterface == ie.SrcInterfaceCPFunction && (!far.DestinationInterfacePresent || far.DestinationInterface == ie.DstInterfaceCPFunction) {
					err = unsupportedRuleIE(ie.DestinationInterface)
				}
				if far.DestinationInterfacePresent && far.DestinationInterface == ie.DstInterfaceCPFunction && far.OuterHeaderCreation != 1 {
					err = unsupportedRuleIE(ie.OuterHeaderCreation)
				}
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

// TS 29.244 V20.1.0 tables 7.5.2.4-1 and 7.5.4.4-1: zero flags keep
// ordinary post-QoS octet measurement. Every active flag changes measurement.
func validateMeasurementInformation(field *ie.IE) error {
	if field == nil || isNullIE(field) {
		return nil
	}
	value, err := field.MeasurementInformation()
	if err != nil {
		return err
	}
	if value != 0 {
		return unsupportedRuleIE(ie.MeasurementInformation)
	}
	return nil
}

// validateRuleNetworkInstances applies the single-domain alias admission policy
// consistently to PDI and FAR provisioning, including modifications.
// TS 29.244 V20.1.0 tables 7.5.2.2-2, 7.5.2.3-2 and 7.5.4.3-2.
func validateRuleNetworkInstances(conn *PfcpConnection, groups ...[]*ie.IE) error {
	for _, rules := range groups {
		for _, rule := range rules {
			var kind uint8
			var id uint32
			var instance *ie.IE
			switch rule.Type {
			case ie.CreatePDR, ie.UpdatePDR:
				kind = ie.RuleIDTypePDR
				var identifier, pdi *ie.IE
				if rule.Type == ie.CreatePDR {
					f, err := rule.CreatePDR()
					if err != nil {
						return err
					}
					identifier, pdi = f.PDRID, f.PDI
				} else {
					f, err := rule.UpdatePDR()
					if err != nil {
						return err
					}
					identifier, pdi = f.PDRID, f.PDI
				}
				value, _ := identifier.PDRID()
				id = uint32(value)
				if pdi != nil {
					f, err := pdi.PDI()
					if err != nil {
						return err
					}
					instance = f.NetworkInstance
				}
			case ie.CreateFAR:
				kind = ie.RuleIDTypeFAR
				f, err := rule.CreateFAR()
				if err != nil {
					return err
				}
				id, _ = f.FARID.FARID()
				if f.ForwardingParameters != nil {
					v, err := f.ForwardingParameters.ForwardingParameters()
					if err != nil {
						return err
					}
					instance = v.NetworkInstance
				}
			case ie.UpdateFAR:
				kind = ie.RuleIDTypeFAR
				f, err := rule.UpdateFAR()
				if err != nil {
					return err
				}
				id, _ = f.FARID.FARID()
				if f.UpdateForwardingParameters != nil {
					v, err := f.UpdateForwardingParameters.UpdateForwardingParameters()
					if err != nil {
						return err
					}
					instance = v.NetworkInstance
				}
			}
			if instance == nil || isNullIE(instance) {
				continue
			}
			// Network Instance can use name syntax. Decode that explicit wire
			// representation for the configured human-readable alias policy.
			name, err := instance.NetworkInstanceHeuristic()
			if err != nil {
				log.Warn().Err(err).Msg("Ignore invalid optional Network Instance")
				continue
			}
			if !conn.ValidateNetworkInstance(name) {
				return &ruleFailure{kind, id, &requestIEError{ie.CauseRuleCreationModificationFailure, ie.NetworkInstance, errNotAllowedNetworkInstance}}
			}
		}
	}
	return nil
}
