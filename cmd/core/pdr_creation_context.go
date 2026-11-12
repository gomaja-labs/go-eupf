// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

var ignoredSDFFilters = promauto.NewCounter(prometheus.CounterOpts{
	Name: "upf_ignored_sdf_filters_total",
	Help: "Semantically incorrect optional SDF filters ignored under TS 29.244 clause 7.6.8",
})

func ignoreSDFFilter(info *SPDRInfo, err error) {
	ignoredSDFFilters.Inc()
	log.Warn().Err(err).Uint64("SEID", info.PdrInfo.SessionID).Uint32("PDRID", info.PdrID).Msg("Ignore semantically incorrect optional SDF Filter")
}

type PDRCreationContext struct {
	Session              *Session
	ResourceManager      *service.ResourceManager
	TEIDCache            map[uint8]uint32
	TEIDSources          map[uint8]uint8
	Restoration          bool
	N3Address, N9Address net.IP
}

func NewPDRCreationContext(session *Session, resourceManager *service.ResourceManager) *PDRCreationContext {
	return &PDRCreationContext{
		Session:         session,
		ResourceManager: resourceManager,
		TEIDCache:       make(map[uint8]uint32),
		TEIDSources:     make(map[uint8]uint8),
	}
}

// GetURRIDs reads the PDR usage-rule list; a null occurrence removes the entire list.
func GetURRIDs(i *ie.IE) ([]uint32, error) {
	var children []*ie.IE
	switch i.Type {
	case ie.CreatePDR:
		f, err := i.CreatePDR()
		if err != nil {
			return nil, err
		}
		children = f.URRID
	case ie.UpdatePDR:
		f, err := i.UpdatePDR()
		if err != nil {
			return nil, err
		}
		children = f.URRID
	default:
		return nil, &ie.InvalidTypeError{Type: i.Type}
	}
	var ids []uint32
	for _, child := range children {
		// TS 29.244 V20.1.0 clauses 5.6.3 and 8.1.2: a null URR ID removes the list.
		if isNullIE(child) {
			return nil, nil
		}
		id, err := child.URRID()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (pdrContext *PDRCreationContext) extractPDR(pdr *ie.IE, spdrInfo *SPDRInfo) error {
	var activate, deactivate, qerIDs []*ie.IE
	var removal, farID, pdiIE, precedence *ie.IE
	var removeURRs bool
	switch pdr.Type {
	case ie.CreatePDR:
		f, err := pdr.CreatePDR()
		if err != nil {
			return err
		}
		activate, qerIDs, removal, farID, pdiIE, precedence = f.ActivatePredefinedRules, f.QERID, f.OuterHeaderRemoval, f.FARID, f.PDI, f.Precedence
	case ie.UpdatePDR:
		f, err := pdr.UpdatePDR()
		if err != nil {
			return err
		}
		activate, deactivate, qerIDs, removal, farID, pdiIE, precedence = f.ActivatePredefinedRules, f.DeactivatePredefinedRules, f.QERID, f.OuterHeaderRemoval, f.FARID, f.PDI, f.Precedence
		for _, id := range f.URRID {
			if isNullIE(id) {
				removeURRs = true
			}
		}
	default:
		return &ie.InvalidTypeError{Type: pdr.Type}
	}
	spdrInfo.AllocatedTEID, spdrInfo.AllocatedUEIP = false, false
	spdrInfo.PdrInfo.PdrID = spdrInfo.PdrID
	if pdrContext.Session != nil {
		spdrInfo.PdrInfo.SessionID = pdrContext.Session.LocalSEID
	}
	if precedence != nil {
		value, err := precedence.Precedence()
		if err != nil {
			return err
		}
		spdrInfo.PdrInfo.Precedence = value
	}
	if removeURRs {
		spdrInfo.PdrInfo.UrrIDs = nil
		spdrInfo.URRIDs = nil
	}
	for _, rule := range activate {
		if ruleName, err := rule.ActivatePredefinedRules(); err == nil {
			log.Debug().Msgf("find activate pcc rule with name: %s", ruleName)

			if spdrInfo.PCCInfo == nil {
				spdrInfo.PCCInfo = &PCCInfo{
					PCCName: ruleName,
				}
			} else {
				spdrInfo.PCCInfo.PCCName = ruleName
			}
		}

	}
	for _, rule := range deactivate {
		if ruleName, err := rule.DeactivatePredefinedRules(); err == nil {
			log.Debug().Msgf("find deactivate pcc rule with name: %s", ruleName)

			if spdrInfo.PCCInfo != nil && spdrInfo.PCCInfo.PCCName == ruleName {
				spdrInfo.PCCInfo = nil
			}
		}

	}
	if isNullIE(removal) {
		spdrInfo.PdrInfo.OuterHeaderRemovalPresent = false
	}
	if outerHeaderRemoval, err := removal.OuterHeaderRemovalDescription(); err == nil {
		spdrInfo.PdrInfo.OuterHeaderRemovalPresent = true
		spdrInfo.PdrInfo.OuterHeaderRemoval = outerHeaderRemoval
	}
	if farid, err := farID.FARID(); err == nil {
		spdrInfo.FARID = &farid
		spdrInfo.PdrInfo.FarId = pdrContext.getFARID(farid)
	}
	// TS 29.244 V20.1.0 clause 5.6.3: one null occurrence removes every binding of that type.
	removeQERs := false
	for _, id := range qerIDs {
		if isNullIE(id) {
			removeQERs = true
		}
	}
	if removeQERs {
		spdrInfo.PdrInfo.QerIDs = nil
		spdrInfo.QERIDs = nil
	} else if len(qerIDs) > 0 {
		if len(qerIDs) > ebpf.MaxQERsPerPDR {
			return ebpf.ErrRuleCapacity
		}
		spdrInfo.PdrInfo.QerIDs = nil
		spdrInfo.QERIDs = nil
		for _, field := range qerIDs {
			id, err := field.QERID()
			if err != nil {
				return err
			}
			spdrInfo.QERIDs = append(spdrInfo.QERIDs, id)
			spdrInfo.PdrInfo.QerIDs = append(spdrInfo.PdrInfo.QerIDs, pdrContext.getQERID(id))
		}
	}
	if !removeURRs {
		ids, err := GetURRIDs(pdr)
		if err != nil {
			return err
		}
		if len(ids) > ebpf.MaxURRsPerPDR {
			return ebpf.ErrRuleCapacity
		}
		if len(ids) > 0 {
			spdrInfo.URRIDs = append([]uint32(nil), ids...)
			spdrInfo.PdrInfo.UrrIDs = nil
			for _, id := range ids {
				spdrInfo.PdrInfo.UrrIDs = append(spdrInfo.PdrInfo.UrrIDs, pdrContext.getURRID(id))
			}
		}
	}

	pdi, err := pdiIE.PDI()
	if err != nil {
		//return fmt.Errorf("PDI IE is missing")
		return nil
	}

	// TS 29.244 V20.1.0 clause 6.3.3.2: an included PDI replaces
	// the complete existing PDI, including fields absent from the new group.
	spdrInfo.LocalFTEIDIPv4 = nil
	spdrInfo.Teid, spdrInfo.Ipv4, spdrInfo.Ipv6 = 0, nil, nil
	spdrInfo.NetworkInstance, spdrInfo.SourceInterface = "", 0
	spdrInfo.PdrInfo.UEIPv4, spdrInfo.PdrInfo.UEIPv6, spdrInfo.PdrInfo.UEIPv6Mask = nil, nil, nil
	spdrInfo.PdrInfo.SourceInterfacePresent, spdrInfo.PdrInfo.UEDestination = false, false
	if ne, err := pdi.NetworkInstance.NetworkInstanceHeuristic(); err == nil {
		spdrInfo.NetworkInstance = ne
	}

	if sourceInterface, err := pdi.SourceInterface.SourceInterface(); err == nil {
		spdrInfo.SourceInterface = sourceInterface
		spdrInfo.PdrInfo.SourceInterface = sourceInterface
		spdrInfo.PdrInfo.SourceInterfacePresent = true
	}

	spdrInfo.PdrInfo.SdfFilter = nil
	spdrInfo.PdrInfo.QFIs = nil
	if len(pdi.QFI) > ebpf.MaxQFIsPerPDR {
		return ebpf.ErrRuleCapacity
	}
	for _, field := range pdi.QFI {
		qfi, err := field.QFI()
		if err != nil {
			return err
		}
		spdrInfo.PdrInfo.QFIs = append(spdrInfo.PdrInfo.QFIs, qfi)
	}
	for _, x := range pdi.SDFFilter {
		{
			if sdfFilter, err := x.SDFFilter(); err == nil {
				if sdfFilter.FlowDescription == "" {
					ignoreSDFFilter(spdrInfo, fmt.Errorf("empty Flow Description"))
				} else if sdfFilterParsed, err := ParseSdfFilter(sdfFilter.FlowDescription); err == nil {
					if spdrInfo.PdrInfo.SdfFilter == nil {
						spdrInfo.PdrInfo.SdfFilter = make([]ebpf.SdfFilter, 0, 2)
					}
					// TS 29.244 V20.1.0 clause 5.2.1A.2A: CP descriptions
					// assume downlink; Access PDRs reverse addresses and ports.
					if spdrInfo.PdrInfo.SourceInterfacePresent && (spdrInfo.SourceInterface == ie.SrcInterfaceAccess) != (sdfFilterParsed.Direction == "in") {
						sdfFilterParsed.SrcAddress, sdfFilterParsed.DstAddress = sdfFilterParsed.DstAddress, sdfFilterParsed.SrcAddress
						sdfFilterParsed.SrcPortRange, sdfFilterParsed.DstPortRange = sdfFilterParsed.DstPortRange, sdfFilterParsed.SrcPortRange
					}
					spdrInfo.PdrInfo.SdfFilter = append(spdrInfo.PdrInfo.SdfFilter, sdfFilterParsed)
					if len(spdrInfo.PdrInfo.SdfFilter) > ebpf.MaxSDFFiltersPerPDR {
						return ebpf.ErrRuleCapacity
					}
				} else {
					if errors.Is(err, ebpf.ErrUnsupportedRuleContent) {
						return err
					}
					// TS 29.244 V20.1.0 clause 7.6.8 and Table 7.5.2.2-2:
					// a semantically incorrect optional SDF Filter is absent.
					ignoreSDFFilter(spdrInfo, err)
				}
			} else {
				ignoreSDFFilter(spdrInfo, err)
			}
		}
	}

	if pdi.LocalFTEID != nil {
		fteid, err := pdi.LocalFTEID.FTEID()
		if err != nil {
			return fmt.Errorf("F-TEID IE is missing")
		}
		// TS 29.244 V20.1.0 clauses 5.5.1, 8.2.3 and Table 7.5.2.1-1 note 4.
		if fteid.HasChID() && !fteid.HasCh() || fteid.Flags&3 == 0 || !fteid.HasCh() && !pdrContext.Restoration && !pdrContext.hasSessionFTEID(fteid.TEID, spdrInfo.SourceInterface, fteid.IPv4Address) {
			return &requestIEError{ie.CauseInvalidFTEIDAllocationOption, ie.FTEID, fmt.Errorf("incompatible F-TEID allocation option")}
		}
		if fteid.Flags&2 != 0 {
			return unsupportedRuleIE(ie.FTEID)
		}
		if !fteid.HasCh() && fteid.TEID == 0 {
			return invalidRequestIE(ie.FTEID, fmt.Errorf("zero user-plane TEID"))
		}
		expected := pdrContext.N3Address
		if spdrInfo.SourceInterface == ie.SrcInterfaceCore {
			expected = pdrContext.N9Address
		}
		if !fteid.HasCh() && expected != nil && !expected.Equal(fteid.IPv4Address) {
			cause := ie.CauseRuleCreationModificationFailure
			if pdrContext.Restoration {
				cause = ie.CauseSessionRestorationResourceUnavailable
			}
			return &requestIEError{cause, ie.FTEID, fmt.Errorf("F-TEID address is not available on the requested interface")}
		}
		spdrInfo.LocalFTEIDIPv4 = cloneIP(fteid.IPv4Address)
		if fteid.HasCh() {
			spdrInfo.LocalFTEIDIPv4 = cloneIP(expected)
		}
		var teid = fteid.TEID
		if fteid.HasCh() {
			var allocate = true
			if fteid.HasChID() {
				if teidFromCache, ok := pdrContext.hasTEIDCache(fteid.ChooseID); ok {
					// Clause 8.2.3 requires the same complete F-TEID, not
					// only the TEID number, for a shared CHOOSE ID.
					if pdrContext.TEIDSources[fteid.ChooseID] != spdrInfo.SourceInterface {
						return &requestIEError{ie.CauseInvalidFTEIDAllocationOption, ie.FTEID, fmt.Errorf("CHOOSE ID spans distinct interface addresses")}
					}
					allocate = false
					teid = teidFromCache
					spdrInfo.AllocatedTEID = true
				}
			}
			if allocate {
				allocatedTeid, err := pdrContext.getFTEID(pdrContext.Session.LocalSEID, spdrInfo.PdrID)
				if err != nil {
					log.Error().Msgf("AllocateTEID err: %v", err)
					return fmt.Errorf("allocate TEID: %w", err)
				}
				teid = allocatedTeid
				spdrInfo.AllocatedTEID = true
				if fteid.HasChID() {
					pdrContext.setTEIDCache(fteid.ChooseID, teid, spdrInfo.SourceInterface)
				}
			}
		}
		if pdrContext.ResourceManager != nil && pdrContext.ResourceManager.FTEIDM != nil {
			if err := pdrContext.ResourceManager.FTEIDM.ReserveTEID(pdrContext.Session.LocalSEID, spdrInfo.PdrID, teid); err != nil {
				return err
			}
		}
		spdrInfo.Teid = teid
	}

	if len(pdi.UEIPAddress) > 0 {
		ueIP, err := pdi.UEIPAddress[0].UEIPAddress()
		if err != nil {
			return fmt.Errorf("UE IP Address IE is missing")
		}
		if hasCHV4(ueIP.Flags) && !config.Conf.FeatureUEIP {
			return unsupportedRuleIE(ie.UEIPAddress)
		}
		if config.Conf.FeatureUEIP && hasCHV4(ueIP.Flags) {
			if ip, err := pdrContext.getIP(); err == nil {
				ueIP.IPv4Address = cloneIP(ip)
				spdrInfo.AllocatedUEIP = true
			} else {
				return fmt.Errorf("allocate UE IP: %w", err)
			}
		}

		if ueIP.IPv4Address == nil && ueIP.IPv6Address == nil {
			return fmt.Errorf("UE IP Address IE is missing")
		}

		spdrInfo.PdrInfo.UEDestination = ueIP.Flags&4 != 0
		if ueIP.IPv4Address != nil {
			spdrInfo.Ipv4 = cloneIP(ueIP.IPv4Address)
			spdrInfo.PdrInfo.UEIPv4 = cloneIP(ueIP.IPv4Address)
		}
		if ueIP.IPv6Address != nil {
			spdrInfo.Ipv6 = cloneIP(ueIP.IPv6Address)
			spdrInfo.PdrInfo.UEIPv6 = cloneIP(ueIP.IPv6Address)
			prefix := 64
			if ueIP.Flags&8 != 0 {
				prefix = 64 - int(ueIP.IPv6PrefixDelegationBits)
			} else if ueIP.Flags&64 != 0 && ueIP.IPv6PrefixLength != 0 {
				prefix = int(ueIP.IPv6PrefixLength)
			}
			if prefix < 0 || prefix > 128 {
				return fmt.Errorf("invalid IPv6 prefix length")
			}
			spdrInfo.PdrInfo.UEIPv6Mask = net.CIDRMask(prefix, 128)
			if pdrContext.ResourceManager != nil && pdrContext.ResourceManager.IPAM != nil {
				if err := pdrContext.ResourceManager.IPAM.ReserveIPv6Prefix(pdrContext.Session.LocalSEID, spdrInfo.Ipv6, spdrInfo.PdrInfo.UEIPv6Mask); err != nil {
					return err
				}
			}
		}
		if pdrContext.ResourceManager != nil && pdrContext.ResourceManager.IPAM != nil {
			for _, ip := range []net.IP{spdrInfo.Ipv4, spdrInfo.Ipv6} {
				if ip != nil {
					if err := pdrContext.ResourceManager.IPAM.ReserveIP(pdrContext.Session.LocalSEID, ip); err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

	if spdrInfo.Teid == 0 && spdrInfo.Ipv4 == nil && spdrInfo.Ipv6 == nil {
		log.Warn().Msg("Both F-TEID IE and UE IP Address IE are missing")
		return fmt.Errorf("both F-TEID IE and UE IP Address IE are missing")
	}

	return nil
}

func (pdrContext *PDRCreationContext) deletePDR(info SPDRInfo, maps ebpf.ForwardingPlaneController) error {
	if info.PCCInfo != nil {
		return nil
	}
	if info.Teid != 0 {
		return maps.DeletePdrUplink(info.Teid, info.PdrInfo.SessionID, info.PdrID)
	}
	if info.Ipv4 != nil {
		if err := maps.DeletePdrDownlink(info.Ipv4, info.PdrInfo.SessionID, info.PdrID); err != nil {
			return err
		}
	}
	if info.Ipv6 != nil {
		prefix, bits := info.PdrInfo.UEIPv6Mask.Size()
		if bits != 128 {
			prefix = 128
		}
		return maps.DeleteDownlinkPdrIp6(info.Ipv6, info.PdrInfo.SessionID, info.PdrID, uint32(prefix))
	}
	return nil
}

func (pdrContext *PDRCreationContext) getFARID(farid uint32) uint32 {
	return pdrContext.Session.GetFar(farid).GlobalId
}

func (pdrContext *PDRCreationContext) getQERID(qerid uint32) uint32 {
	return pdrContext.Session.GetQer(qerid).GlobalId
}

func (pdrContext *PDRCreationContext) getURRID(urrid uint32) uint32 {
	return pdrContext.Session.GetUrr(urrid).GlobalId
}

func (pdrContext *PDRCreationContext) getFTEID(seID uint64, pdrID uint32) (uint32, error) {
	if pdrContext.ResourceManager == nil || pdrContext.ResourceManager.FTEIDM == nil {
		return 0, errors.New("FTEID manager is nil")
	}

	allocatedTeid, err := pdrContext.ResourceManager.FTEIDM.AllocateTEID(seID, pdrID)
	if err != nil {
		log.Error().Msgf("AllocateTEID err: %v", err)
		return 0, fmt.Errorf("allocate TEID: %w", err)
	}
	return allocatedTeid, nil
}

func (pdrContext PDRCreationContext) getIP() (net.IP, error) {
	if pdrContext.ResourceManager == nil || pdrContext.ResourceManager.IPAM == nil {
		return nil, errors.New("IP address manager is nil")
	}
	allocatedIP, err := pdrContext.ResourceManager.IPAM.AllocateIP(pdrContext.Session.LocalSEID)
	if err != nil {
		return nil, fmt.Errorf("allocate UE IP: %w", err)
	}
	return allocatedIP, nil
}

func (pdrContext *PDRCreationContext) hasTEIDCache(chooseID uint8) (uint32, bool) {
	teid, ok := pdrContext.TEIDCache[chooseID]
	return teid, ok
}

func (pdrContext *PDRCreationContext) setTEIDCache(chooseID uint8, teid uint32, source uint8) {
	pdrContext.TEIDCache[chooseID] = teid
	pdrContext.TEIDSources[chooseID] = source
}

func hasCHV4(flags uint8) bool {
	return flags&(1<<4) != 0
}

// isNullIE distinguishes a present removal instruction from an absent field.
// TS 29.244 V20.1.0 clauses 5.6.3 and 8.1.2.
func isNullIE(value *ie.IE) bool {
	return value != nil && len(value.Payload) == 0 && len(value.ChildIEs) == 0
}

// resolvePDRSlots binds only rules from this session, after slot reservation.
// The logical references remain in the draft for subsequent modifications.
func resolvePDRSlots(info *SPDRInfo, session *Session) error {
	if info.FARID != nil {
		rule, ok := session.FARs[*info.FARID]
		if !ok || rule.GlobalId == 0 {
			return fmt.Errorf("FAR binding is not assigned")
		}
		info.PdrInfo.FarId = rule.GlobalId
	}
	if info.QERIDs != nil {
		info.PdrInfo.QerIDs = nil
		for _, id := range info.QERIDs {
			rule, ok := session.QERs[id]
			if !ok || rule.GlobalId == 0 {
				return fmt.Errorf("QER binding is not assigned")
			}
			info.PdrInfo.QerIDs = append(info.PdrInfo.QerIDs, rule.GlobalId)
		}
	}
	if info.URRIDs != nil {
		info.PdrInfo.UrrIDs = nil
		for _, id := range info.URRIDs {
			rule, ok := session.URRs[id]
			if !ok || rule.GlobalId == 0 {
				return fmt.Errorf("URR binding is not assigned")
			}
			info.PdrInfo.UrrIDs = append(info.PdrInfo.UrrIDs, rule.GlobalId)
		}
	}
	return nil
}

// hasSessionFTEID permits referencing an existing UP-allocated tunnel without
// treating the reference as a new CP allocation (TS 29.244 clause 5.5.1).
func (pdrContext *PDRCreationContext) hasSessionFTEID(teid uint32, source uint8, address net.IP) bool {
	if pdrContext.Session == nil || address == nil {
		return false
	}
	for _, pdr := range pdrContext.Session.PDRs {
		if pdr.Teid == teid && pdr.SourceInterface == source && pdr.LocalFTEIDIPv4.Equal(address) {
			return true
		}
	}
	return false
}

// bindAssignedAddresses resolves RFC 6733 section 4.3.1's terminal address set
// after all PDIs and address allocations in the request have been processed.
func (conn *PfcpConnection) bindAssignedAddresses(session *Session) error {
	hasAssigned := false
	for _, pdr := range session.PDRs {
		for _, f := range pdr.PdrInfo.SdfFilter {
			hasAssigned = hasAssigned || f.SrcAddress.Type == 3 || f.DstAddress.Type == 3
		}
	}
	if !hasAssigned {
		return nil
	}
	var ip4, ip6 net.IP
	var mask6 net.IPMask
	for id, pdr := range session.PDRs {
		if pdr.Ipv4 != nil {
			if ip4 != nil && !ip4.Equal(pdr.Ipv4) {
				return &ruleFailure{ie.RuleIDTypePDR, id, fmt.Errorf("multiple assigned IPv4 addresses: %w", ebpf.ErrUnsupportedRuleContent)}
			}
			ip4 = pdr.Ipv4
		}
		if pdr.Ipv6 != nil {
			candidate := pdr.Ipv6.Mask(pdr.PdrInfo.UEIPv6Mask)
			if ip6 != nil && (!ip6.Equal(candidate) || !bytes.Equal(mask6, pdr.PdrInfo.UEIPv6Mask)) {
				return &ruleFailure{ie.RuleIDTypePDR, id, fmt.Errorf("multiple assigned IPv6 prefixes: %w", ebpf.ErrUnsupportedRuleContent)}
			}
			ip6, mask6 = candidate, pdr.PdrInfo.UEIPv6Mask
		}
	}
	for id, pdr := range session.PDRs {
		assigned := false
		for _, filter := range pdr.PdrInfo.SdfFilter {
			assigned = assigned || filter.SrcAddress.Type == 3 || filter.DstAddress.Type == 3
		}
		if !assigned {
			continue
		}
		if ip4 == nil && ip6 == nil {
			return &ruleFailure{ie.RuleIDTypePDR, id, fmt.Errorf("assigned address is unavailable: %w", ebpf.ErrUnsupportedRuleContent)}
		}
		if pdr.PdrInfo.AssignedIPv4.Equal(ip4) && pdr.PdrInfo.AssignedIPv6.Equal(ip6) && bytes.Equal(pdr.PdrInfo.AssignedIPv6Mask, mask6) {
			continue
		}
		pdr.PdrInfo.AssignedIPv4, pdr.PdrInfo.AssignedIPv6 = cloneIP(ip4), cloneIP(ip6)
		pdr.PdrInfo.AssignedIPv6Mask = append(net.IPMask(nil), mask6...)
		if err := applyPDR(pdr, conn.mapOperations); err != nil {
			return &ruleFailure{ie.RuleIDTypePDR, id, err}
		}
		session.PDRs[id] = pdr
	}
	return nil
}

// deleteReplacedPDR removes only keys not replaced by the PDR's single-key
// publication. The old key remains usable until the new key has been installed.
func (pdrContext *PDRCreationContext) deleteReplacedPDR(old, current SPDRInfo, maps ebpf.ForwardingPlaneController) error {
	if old.Teid != 0 {
		if old.Teid == current.Teid {
			return nil
		}
		return maps.DeletePdrUplink(old.Teid, old.PdrInfo.SessionID, old.PdrID)
	}
	if old.Ipv4 != nil && (current.Teid != 0 || !old.Ipv4.Equal(current.Ipv4)) {
		if err := maps.DeletePdrDownlink(old.Ipv4, old.PdrInfo.SessionID, old.PdrID); err != nil {
			return err
		}
	}
	if old.Ipv6 != nil && (current.Teid != 0 || !old.Ipv6.Equal(current.Ipv6) || !bytes.Equal(old.PdrInfo.UEIPv6Mask, current.PdrInfo.UEIPv6Mask)) {
		prefix, bits := old.PdrInfo.UEIPv6Mask.Size()
		if bits != 128 {
			prefix = 128
		}
		return maps.DeleteDownlinkPdrIp6(old.Ipv6, old.PdrInfo.SessionID, old.PdrID, uint32(prefix))
	}
	return nil
}
