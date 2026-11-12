// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"net"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/rs/zerolog/log"
)

type PDRCreationContext struct {
	Session         *Session
	ResourceManager *service.ResourceManager
	TEIDCache       map[uint8]uint32
}

func NewPDRCreationContext(session *Session, resourceManager *service.ResourceManager) *PDRCreationContext {
	return &PDRCreationContext{
		Session:         session,
		ResourceManager: resourceManager,
		TEIDCache:       make(map[uint8]uint32),
	}
}

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
		if len(child.Payload) == 0 && len(child.ChildIEs) == 0 {
			continue
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
	var removal, farID, pdiIE *ie.IE
	var removeURRs bool
	switch pdr.Type {
	case ie.CreatePDR:
		f, err := pdr.CreatePDR()
		if err != nil {
			return err
		}
		activate, qerIDs, removal, farID, pdiIE = f.ActivatePredefinedRules, f.QERID, f.OuterHeaderRemoval, f.FARID, f.PDI
	case ie.UpdatePDR:
		f, err := pdr.UpdatePDR()
		if err != nil {
			return err
		}
		activate, deactivate, qerIDs, removal, farID, pdiIE = f.ActivatePredefinedRules, f.DeactivatePredefinedRules, f.QERID, f.OuterHeaderRemoval, f.FARID, f.PDI
		for _, id := range f.URRID {
			if len(id.Payload) == 0 && len(id.ChildIEs) == 0 {
				removeURRs = true
			}
		}
	default:
		return &ie.InvalidTypeError{Type: pdr.Type}
	}
	if removeURRs {
		spdrInfo.PdrInfo.Urr1Id, spdrInfo.PdrInfo.Urr2Id = 0, 0
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
	if outerHeaderRemoval, err := removal.OuterHeaderRemovalDescription(); err == nil {
		spdrInfo.PdrInfo.OuterHeaderRemoval = outerHeaderRemoval
	}
	if farid, err := farID.FARID(); err == nil {
		spdrInfo.PdrInfo.FarId = pdrContext.getFARID(farid)
	}
	for _, id := range qerIDs {
		if qerid, err := id.QERID(); err == nil {
			spdrInfo.PdrInfo.QerId = pdrContext.getQERID(qerid)
		}

	}
	if urrs, err := GetURRIDs(pdr); err == nil {
		if len(urrs) > 0 {
			spdrInfo.PdrInfo.Urr1Id = pdrContext.getURRID(urrs[0])
		}

		if len(urrs) > 1 {
			spdrInfo.PdrInfo.Urr2Id = pdrContext.getURRID(urrs[1])
		}
	}

	pdi, err := pdiIE.PDI()
	if err != nil {
		//return fmt.Errorf("PDI IE is missing")
		return nil
	}

	if ne, err := pdi.NetworkInstance.NetworkInstance(); err == nil {
		spdrInfo.NetworkInstance = ne
	}

	if sourceInterface, err := pdi.SourceInterface.SourceInterface(); err == nil {
		spdrInfo.SourceInterface = sourceInterface
	}

	for _, x := range pdi.SDFFilter {
		{
			if sdfFilter, err := x.SDFFilter(); err == nil {
				if sdfFilter.FlowDescription == "" {
					log.Warn().Msgf("SDFFilter is empty")
				} else if sdfFilterParsed, err := ParseSdfFilter(sdfFilter.FlowDescription); err == nil {
					if spdrInfo.PdrInfo.SdfFilter == nil {
						spdrInfo.PdrInfo.SdfFilter = make([]ebpf.SdfFilter, 0, 2)
					}
					spdrInfo.PdrInfo.SdfFilter = append(spdrInfo.PdrInfo.SdfFilter, sdfFilterParsed)
				} else {
					log.Error().Msgf("SDFFilter err: %v", err)
					return err
				}
			}
		}
	}

	if pdi.LocalFTEID != nil {
		fteid, err := pdi.LocalFTEID.FTEID()
		if err != nil {
			return fmt.Errorf("F-TEID IE is missing")
		}
		var teid = fteid.TEID
		if fteid.HasCh() {
			var allocate = true
			if fteid.HasChID() {
				if teidFromCache, ok := pdrContext.hasTEIDCache(fteid.ChooseID); ok {
					allocate = false
					teid = teidFromCache
					spdrInfo.Allocated = true
				}
			}
			if allocate {
				allocatedTeid, err := pdrContext.getFTEID(pdrContext.Session.RemoteSEID, spdrInfo.PdrID)
				if err != nil {
					log.Error().Msgf("AllocateTEID err: %v", err)
					return fmt.Errorf("can't allocate TEID: %s", causeToString(ie.CauseNoResourcesAvailable))
				}
				teid = allocatedTeid
				spdrInfo.Allocated = true
				if fteid.HasChID() {
					pdrContext.setTEIDCache(fteid.ChooseID, teid)
				}
			}
		}
		spdrInfo.Teid = teid
		return nil
	}

	for _, address := range pdi.UEIPAddress {
		ueIP, err := address.UEIPAddress()
		if err != nil {
			return fmt.Errorf("UE IP Address IE is missing")
		}
		if config.Conf.FeatureUEIP && hasCHV4(ueIP.Flags) {
			if ip, err := pdrContext.getIP(); err == nil {
				ueIP.IPv4Address = cloneIP(ip)
				spdrInfo.Allocated = true
			} else {
				log.Error().Msg(err.Error())
			}
		}

		if ueIP.IPv4Address == nil && ueIP.IPv6Address == nil {
			return fmt.Errorf("UE IP Address IE is missing")
		}

		if ueIP.IPv4Address != nil {
			spdrInfo.Ipv4 = cloneIP(ueIP.IPv4Address)
		}
		if ueIP.IPv6Address != nil {
			spdrInfo.Ipv6 = cloneIP(ueIP.IPv6Address)
		}
		return nil
	}

	if spdrInfo.Teid == 0 && spdrInfo.Ipv4 == nil && spdrInfo.Ipv6 == nil {
		log.Warn().Msg("Both F-TEID IE and UE IP Address IE are missing")
		return fmt.Errorf("both F-TEID IE and UE IP Address IE are missing")
	}

	return nil
}

func (pdrContext *PDRCreationContext) deletePDR(spdrInfo SPDRInfo, mapOperations ebpf.ForwardingPlaneController) error {
	if spdrInfo.PCCInfo != nil {
		// todo: process pcc rule
		return nil
	}

	//FIXME: Assume that PDR with SDF filter will never been deleting last
	if spdrInfo.PdrInfo.SdfFilter != nil {
		return nil
	}

	if spdrInfo.Teid > 0 {
		if _, ok := pdrContext.TEIDCache[uint8(spdrInfo.Teid)]; !ok {
			if err := mapOperations.DeletePdrUplink(spdrInfo.Teid); err != nil {
				//return fmt.Errorf("can't delete GTP PDR: %s", err.Error())
				log.Warn().Msgf("can't delete GTP PDR: %s", err.Error())
			}
			pdrContext.TEIDCache[uint8(spdrInfo.Teid)] = 0
		}

		if pdrContext.ResourceManager != nil {
			pdrContext.ResourceManager.FTEIDM.ReleaseTEID(pdrContext.Session.RemoteSEID)
		}
	} else {
		if spdrInfo.Ipv4 != nil {
			if err := mapOperations.DeletePdrDownlink(spdrInfo.Ipv4); err != nil {
				//return fmt.Errorf("can't delete IPv4 PDR: %s", err.Error())
				log.Warn().Msgf("can't delete IPv4 PDR: %s", err.Error())
			}
		}

		if spdrInfo.Ipv6 != nil {
			if err := mapOperations.DeleteDownlinkPdrIp6(spdrInfo.Ipv6); err != nil {
				return fmt.Errorf("can't delete IPv6 PDR: %s", err.Error())
			}
		}
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
		return 0, fmt.Errorf("can't allocate TEID: %s", causeToString(ie.CauseNoResourcesAvailable))
	}
	return allocatedTeid, nil
}

func (pdrContext PDRCreationContext) getIP() (net.IP, error) {
	if pdrContext.ResourceManager == nil || pdrContext.ResourceManager.IPAM == nil {
		return nil, errors.New("IP address manager is nil")
	}
	allocatedIP, err := pdrContext.ResourceManager.IPAM.AllocateIP(pdrContext.Session.RemoteSEID)
	if err != nil {
		return nil, fmt.Errorf("can't allocate IP: %s", causeToString(ie.CauseNoResourcesAvailable))
	}
	return allocatedIP, nil
}

func (pdrContext *PDRCreationContext) hasTEIDCache(chooseID uint8) (uint32, bool) {
	teid, ok := pdrContext.TEIDCache[chooseID]
	return teid, ok
}

func (pdrContext *PDRCreationContext) setTEIDCache(chooseID uint8, teid uint32) {
	pdrContext.TEIDCache[chooseID] = teid
}

func hasCHV4(flags uint8) bool {
	return flags&(1<<4) != 0
}
