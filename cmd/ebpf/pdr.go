// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package ebpf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"syscall"

	"github.com/cilium/ebpf"

	"github.com/rs/zerolog/log"
)

// The BPF_ARRAY map type has no delete operation. The only way to delete an element is to replace it with a new one.

// isKeyAbsent reports whether an eBPF map operation failed because the key
// does not exist. Delete operations treat that as success: the desired end
// state — the entry being absent — is already achieved.
func isKeyAbsent(err error) bool {
	return err != nil && (errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, syscall.ENOENT))
}

// Fixed bounds are rejected before map writes, never silently truncated.
const (
	MaxQERsPerPDR       = 4
	MaxURRsPerPDR       = 3
	MaxPDRsPerKey       = 4
	MaxSDFFiltersPerPDR = 5
	MaxQFIsPerPDR       = 8
)

var ErrRuleCapacity = errors.New("rule capacity exceeded")
var ErrKeyOwned = errors.New("lookup key belongs to another session")
var ErrUnsupportedRuleContent = errors.New("rule content is not supported")

type PdrInfo struct {
	ReturnFarID               uint32      `json:"return_far_id"`
	ReturnQerIDs              []uint32    `json:"return_qer_ids"`
	ReturnNR                  bool        `json:"return_nr"`
	SessionID                 uint64      `json:"session_id"`
	PdrID                     uint32      `json:"pdr_id"`
	Precedence                uint32      `json:"precedence"`
	OuterHeaderRemovalPresent bool        `json:"outer_header_removal_present"`
	OuterHeaderRemoval        uint8       `json:"outer_header_removal"`
	FarId                     uint32      `json:"far_id"`
	QerIDs                    []uint32    `json:"qer_ids"`
	UrrIDs                    []uint32    `json:"urr_ids"`
	SdfFilter                 []SdfFilter `json:"sdf_filters"`
	QFIs                      []uint8     `json:"qfis"`
	AssignedIPv4              net.IP      `json:"assigned_ipv4"`
	AssignedIPv6              net.IP      `json:"assigned_ipv6"`
	AssignedIPv6Mask          net.IPMask  `json:"assigned_ipv6_mask"`
	UEIPv4                    net.IP      `json:"ue_ipv4"`
	UEIPv6                    net.IP      `json:"ue_ipv6"`
	UEIPv6Mask                net.IPMask  `json:"ue_ipv6_mask"`
	UEDestination             bool        `json:"ue_destination"`
	SourceInterface           uint8       `json:"source_interface"`
	SourceInterfacePresent    bool        `json:"source_interface_present"`
	TraceFlag                 bool        `json:"trace"`
	NotifyFlag                bool        `json:"notify"`
	NRFlag                    bool        `json:"nr"`
}

// SDFProtocolAny is distinct from all eight-bit IP protocol numbers.
const SDFProtocolAny uint16 = 256

type SdfFilter struct {
	Direction    string `json:"direction,omitempty"`
	Protocol     uint16 // IP protocol number, or SDFProtocolAny
	PortsPresent bool
	SrcAddress   IpWMask
	SrcPortRange PortRange
	DstAddress   IpWMask
	DstPortRange PortRange
}

type IpWMask struct {
	Type uint8 // 0: any, 1: ip4, 2: ip6, 3: session-assigned addresses
	Ip   net.IP
	Mask net.IPMask
}

type PortRange struct {
	LowerBound uint16
	UpperBound uint16
}

func preparePDR(lookup func(interface{}, interface{}) error, key interface{}, info PdrInfo) (IpEntrypointPdrInfo, error) {
	var bucket IpEntrypointPdrInfo
	if err := lookup(key, &bucket); err != nil && !isKeyAbsent(err) {
		return bucket, fmt.Errorf("lookup PDR: %w", err)
	}
	if bucket.Count > MaxPDRsPerKey {
		return bucket, fmt.Errorf("invalid PDR count %d", bucket.Count)
	}
	if bucket.Count != 0 && bucket.SessionId != info.SessionID {
		return bucket, ErrKeyOwned
	}
	entry, err := encodePDR(info)
	if err != nil {
		return bucket, err
	}
	bucket.SessionId = info.SessionID
	index := int(bucket.Count)
	for i := 0; i < int(bucket.Count); i++ {
		if bucket.Entries[i].PdrId == info.PdrID {
			index = i
			break
		}
	}
	if index == MaxPDRsPerKey {
		return bucket, ErrRuleCapacity
	}
	bucket.Entries[index] = entry
	if index == int(bucket.Count) {
		bucket.Count++
	}
	sort.Slice(bucket.Entries[:bucket.Count], func(i, j int) bool {
		a, b := bucket.Entries[i], bucket.Entries[j]
		if a.Precedence != b.Precedence {
			return a.Precedence < b.Precedence
		}
		return a.PdrId < b.PdrId
	})
	return bucket, nil
}

func (b *BpfObjects) PutPdrUplink(teid uint32, info PdrInfo) error {
	bucket, err := preparePDR(b.PdrMapTeidIp4.Lookup, teid, info)
	if err != nil {
		return err
	}
	return b.PdrMapTeidIp4.Put(teid, &bucket)
}
func (b *BpfObjects) PutPdrDownlink(ip net.IP, info PdrInfo) error {
	return b.putPdrDownlink(ip, info)
}
func (b *BpfObjects) putPdrDownlink(ip net.IP, info PdrInfo) error {
	m, key, err := b.downlinkRuleMap(ip, info.UEIPv6Mask)
	if err != nil {
		return err
	}
	if ip.To4() == nil {
		if err := b.checkIPv6Overlap(key.(IpEntrypointIpv6PdrKey), info.SessionID); err != nil {
			return err
		}
	}
	bucket, err := preparePDR(func(k, v interface{}) error { return lookupRuleValue(m, k, v) }, key, info)
	if err != nil {
		return err
	}
	return m.Put(key, &bucket)
}
func (b *BpfObjects) UpdatePdrUplink(teid uint32, info PdrInfo) error {
	return b.PutPdrUplink(teid, info)
}
func (b *BpfObjects) UpdatePdrDownlink(ip net.IP, info PdrInfo) error {
	return b.PutPdrDownlink(ip, info)
}

func deletePDR(m *ebpf.Map, key interface{}, sessionID uint64, pdrID uint32) error {
	var bucket IpEntrypointPdrInfo
	if err := lookupRuleValue(m, key, &bucket); err != nil {
		if isKeyAbsent(err) {
			return nil
		}
		return err
	}
	if bucket.SessionId != sessionID {
		return ErrKeyOwned
	}
	if bucket.Count > MaxPDRsPerKey {
		return fmt.Errorf("invalid PDR count %d", bucket.Count)
	}
	for i := 0; i < int(bucket.Count); i++ {
		if bucket.Entries[i].PdrId != pdrID {
			continue
		}
		copy(bucket.Entries[i:], bucket.Entries[i+1:bucket.Count])
		bucket.Count--
		bucket.Entries[bucket.Count] = IpEntrypointPdrEntry{}
		if bucket.Count == 0 {
			return m.Delete(key)
		}
		return m.Put(key, &bucket)
	}
	return nil
}
func (b *BpfObjects) DeletePdrUplink(teid uint32, sessionID uint64, pdrID uint32) error {
	return deletePDR(b.PdrMapTeidIp4, teid, sessionID, pdrID)
}
func (b *BpfObjects) DeletePdrDownlink(ip net.IP, sessionID uint64, pdrID uint32) error {
	m, key, err := b.downlinkMap(ip)
	if err != nil {
		return err
	}
	return deletePDR(m, key, sessionID, pdrID)
}
func (b *BpfObjects) PutDownlinkPdrIp6(ip net.IP, info PdrInfo) error {
	return b.PutPdrDownlink(ip, info)
}
func (b *BpfObjects) UpdateDownlinkPdrIp6(ip net.IP, info PdrInfo) error {
	return b.PutPdrDownlink(ip, info)
}
func (b *BpfObjects) DeleteDownlinkPdrIp6(ip net.IP, sessionID uint64, pdrID uint32, prefixLength uint32) error {
	m, key, err := b.downlinkRuleMap(ip, net.CIDRMask(int(prefixLength), 128))
	if err != nil {
		return err
	}
	return deletePDR(m, key, sessionID, pdrID)
}

type FarInfo struct {
	Action                uint8
	OuterHeaderCreation   uint8
	Teid                  uint32
	RemoteIP              uint32
	Trigger               uint8 // trigger for applying the FAR // todo maxim: change to ringbuffer
	TransportLevelMarking uint16
}

func (f FarInfo) MarshalJSON() ([]byte, error) {
	remoteIP := make(net.IP, 4)
	binary.LittleEndian.PutUint32(remoteIP, f.RemoteIP)
	data := map[string]interface{}{
		"action":                  f.Action,
		"outer_header_creation":   f.OuterHeaderCreation,
		"teid":                    f.Teid,
		"remote_ip":               remoteIP.String(),
		"transport_level_marking": f.TransportLevelMarking,
	}
	return json.Marshal(data)
}

func (bpfObjects *BpfObjects) NewFar(farInfo FarInfo) (uint32, error) {
	internalId, err := bpfObjects.GetNextFAR()
	if err != nil {
		return 0, err
	}

	log.Debug().Msgf("EBPF: Put FAR: internalId=%d, farInfo=%+v", internalId, farInfo)

	farToStore := IpEntrypointFarInfo{
		Action:                farInfo.Action,
		OuterHeaderCreation:   farInfo.OuterHeaderCreation,
		Teid:                  farInfo.Teid,
		Remoteip:              farInfo.RemoteIP,
		TransportLevelMarking: farInfo.TransportLevelMarking,
	}
	if err := bpfObjects.FarMap.Put(internalId, &farToStore); err != nil {
		bpfObjects.ReleaseFAR(internalId)
		return 0, fmt.Errorf("create FAR: %w", err)
	}
	return internalId, nil
}

func (bpfObjects *BpfObjects) GetFar(internalId uint32) (FarInfo, error) {
	log.Debug().Msgf("EBPF: Get FAR: internalId=%d", internalId)

	farToStore := IpEntrypointFarInfo{}
	if err := bpfObjects.FarMap.Lookup(internalId, &farToStore); err != nil {
		return FarInfo{}, err
	}

	farInfo := FarInfo{
		Action:                farToStore.Action,
		OuterHeaderCreation:   farToStore.OuterHeaderCreation,
		Teid:                  farToStore.Teid,
		RemoteIP:              farToStore.Remoteip,
		Trigger:               farToStore.Trigger,
		TransportLevelMarking: farToStore.TransportLevelMarking,
	}

	log.Debug().Msgf("EBPF: Get FAR: internalId=%d, farInfo=%+v", internalId, farInfo)
	return farInfo, nil
}

func (bpfObjects *BpfObjects) UpdateFar(internalId uint32, farInfo FarInfo) error {
	if internalId == 0 {
		return fmt.Errorf("cannot update reserved FAR 0")
	}
	log.Debug().Msgf("EBPF: Update FAR: internalId=%d, farInfo=%+v", internalId, farInfo)

	farToStore := IpEntrypointFarInfo{
		Action:                farInfo.Action,
		OuterHeaderCreation:   farInfo.OuterHeaderCreation,
		Teid:                  farInfo.Teid,
		Remoteip:              farInfo.RemoteIP,
		TransportLevelMarking: farInfo.TransportLevelMarking,
	}
	return bpfObjects.FarMap.Update(internalId, &farToStore, ebpf.UpdateExist)
}

func (bpfObjects *BpfObjects) DeleteFar(intenalId uint32) error {
	if intenalId == 0 {
		return fmt.Errorf("cannot delete reserved Far 0")
	}
	log.Debug().Msgf("EBPF: Delete FAR: intenalId=%d", intenalId)
	if err := bpfObjects.FarMap.Update(intenalId, &IpEntrypointFarInfo{}, ebpf.UpdateExist); err != nil && !isKeyAbsent(err) {
		return err
	}
	bpfObjects.ReleaseFAR(intenalId)
	return nil
}

type QerInfo struct {
	GateStatusUL uint8
	GateStatusDL uint8
	QFIPresent   bool
	RQI          uint8
	Qfi          uint8
	Dscp         uint8
	MaxBitrateUL uint64
	MaxBitrateDL uint64
}

func (bpfObjects *BpfObjects) NewQer(qerInfo QerInfo) (uint32, error) {
	internalId, err := bpfObjects.GetNextQER()
	if err != nil {
		return 0, err
	}
	log.Debug().Msgf("EBPF: Put QER: internalId=%d, qerInfo=%+v", internalId, qerInfo)

	qerToStore := qerMapValue(qerInfo)
	if err := bpfObjects.QerMap.Put(internalId, &qerToStore); err != nil {
		bpfObjects.ReleaseQER(internalId)
		return 0, fmt.Errorf("create QER: %w", err)
	}
	return internalId, nil
}

func (bpfObjects *BpfObjects) UpdateQer(internalId uint32, qerInfo QerInfo) error {
	if internalId == 0 {
		return fmt.Errorf("cannot update reserved QER 0")
	}
	var previous IpEntrypointQerInfo
	if err := bpfObjects.QerMap.Lookup(internalId, &previous); err != nil {
		return err
	}
	log.Debug().Msgf("EBPF: Update QER: internalId=%d, qerInfo=%+v", internalId, qerInfo)

	qerToStore := qerMapValue(qerInfo)
	qerToStore.UlStart, qerToStore.DlStart = previous.UlStart, previous.DlStart
	return bpfObjects.QerMap.Update(internalId, &qerToStore, ebpf.UpdateExist)
}

func (bpfObjects *BpfObjects) DeleteQer(internalId uint32) error {
	if internalId == 0 {
		return fmt.Errorf("cannot delete reserved Qer 0")
	}
	log.Debug().Msgf("EBPF: Delete QER: internalId=%d", internalId)
	if err := bpfObjects.QerMap.Update(internalId, &IpEntrypointQerInfo{}, ebpf.UpdateExist); err != nil && !isKeyAbsent(err) {
		return err
	}
	bpfObjects.ReleaseQER(internalId)
	return nil
}

// TODO: add required fields and implement methods
type UrrInfo struct {
	UplinkVolume    uint64
	DownlinkVolume  uint64
	VolumeThreshold uint64
	VolumeTrigger   bool
	VolumeReported  bool
}

func (bpfObjects *BpfObjects) NewUrr(urrInfo UrrInfo) (uint32, error) {
	internalId, err := bpfObjects.GetNextURR()
	if err != nil {
		return 0, err
	}
	log.Debug().Msgf("EBPF: Put URR: internalId=%d, urrInfo=%+v", internalId, urrInfo)

	urrToStore := IpEntrypointUrrInfo{
		Ul: urrInfo.UplinkVolume,
		Dl: urrInfo.DownlinkVolume,
	}

	if err := bpfObjects.UrrMap.Put(internalId, &urrToStore); err != nil {
		bpfObjects.ReleaseURR(internalId)
		return 0, fmt.Errorf("create URR: %w", err)
	}
	return internalId, nil
}

func (bpfObjects *BpfObjects) UpdateUrr(internalId uint32, urrInfo UrrInfo) error {
	log.Debug().Msgf("EBPF: Update URR: internalId=%d, urrInfo=%+v", internalId, urrInfo)

	// TS 29.244 V20.1.0 clause 5.2.2.2.1: a URR configuration update
	// must preserve traffic counted since the last report. Thresholds live
	// in the control plane; only creation/deletion may initialize counters.
	if internalId == 0 {
		return fmt.Errorf("cannot update reserved URR 0")
	}
	_, err := bpfObjects.GetUrr(internalId)
	return err
}

func (bpfObjects *BpfObjects) GetUrr(internalId uint32) (UrrInfo, error) {
	log.Debug().Msgf("EBPF: Get URR: internalId=%d", internalId)

	urrToStore := IpEntrypointUrrInfo{}
	if err := bpfObjects.UrrMap.Lookup(internalId, &urrToStore); err != nil {
		return UrrInfo{}, err
	}

	urrInfo := UrrInfo{
		UplinkVolume:   urrToStore.Ul,
		DownlinkVolume: urrToStore.Dl,
	}
	return urrInfo, nil
}

func (bpfObjects *BpfObjects) DeleteUrr(internalId uint32) (UrrInfo, error) {
	if internalId == 0 {
		return UrrInfo{}, fmt.Errorf("cannot delete reserved URR 0")
	}
	log.Debug().Msgf("EBPF: Delete URR: internalId=%d", internalId)

	urrToStore := IpEntrypointUrrInfo{}
	if err := bpfObjects.UrrMap.Lookup(internalId, &urrToStore); err != nil {
		if isKeyAbsent(err) {
			return UrrInfo{}, nil
		}
		return UrrInfo{}, err
	}
	if err := bpfObjects.UrrMap.Update(internalId, &IpEntrypointUrrInfo{}, ebpf.UpdateExist); err != nil && !isKeyAbsent(err) {
		return UrrInfo{}, err
	}

	bpfObjects.ReleaseURR(internalId)
	urrInfo := UrrInfo{
		UplinkVolume:   urrToStore.Ul,
		DownlinkVolume: urrToStore.Dl,
	}
	return urrInfo, nil
}

type ForwardingPlaneController interface {
	BeginRuleTransaction(sessionID uint64) (RuleTransaction, error)
	CheckPDRPlan(sessionID uint64, keys []PDRKey) error
	GetNextFAR() (uint32, error)
	GetNextQER() (uint32, error)
	GetNextURR() (uint32, error)
	PutPdrUplink(teid uint32, pdrInfo PdrInfo) error
	PutPdrDownlink(ipv4 net.IP, pdrInfo PdrInfo) error
	PutDownlinkPdrIp6(ipv6 net.IP, pdrInfo PdrInfo) error
	UpdatePdrUplink(teid uint32, pdrInfo PdrInfo) error
	UpdatePdrDownlink(ipv4 net.IP, pdrInfo PdrInfo) error
	DeletePdrUplink(teid uint32, sessionID uint64, pdrID uint32) error
	DeletePdrDownlink(ipv4 net.IP, sessionID uint64, pdrID uint32) error
	UpdateDownlinkPdrIp6(ipv6 net.IP, pdrInfo PdrInfo) error
	DeleteDownlinkPdrIp6(ipv6 net.IP, sessionID uint64, pdrID uint32, prefixLength uint32) error
	NewFar(farInfo FarInfo) (uint32, error)
	GetFar(internalId uint32) (FarInfo, error)
	UpdateFar(internalId uint32, farInfo FarInfo) error
	DeleteFar(internalId uint32) error
	NewQer(qerInfo QerInfo) (uint32, error)
	UpdateQer(internalId uint32, qerInfo QerInfo) error
	DeleteQer(internalId uint32) error
	NewUrr(urrInfo UrrInfo) (uint32, error)
	UpdateUrr(internalId uint32, urrInfo UrrInfo) error
	GetUrr(internalId uint32) (UrrInfo, error)
	ResetUrr(internalId uint32) error
	DetachRule(kind uint8, id uint32) error
	SynchronizeRules() error
	DeleteUrr(internalId uint32) (UrrInfo, error)
}

func encodePDR(info PdrInfo) (IpEntrypointPdrEntry, error) {
	var entry IpEntrypointPdrEntry
	if len(info.SdfFilter) > MaxSDFFiltersPerPDR || len(info.QFIs) > MaxQFIsPerPDR || len(info.ReturnQerIDs) > MaxQERsPerPDR || len(info.QerIDs) > MaxQERsPerPDR || len(info.UrrIDs) > MaxURRsPerPDR {
		return entry, ErrRuleCapacity
	}
	entry.PdrId, entry.Precedence = info.PdrID, info.Precedence
	// Common unfiltered PDRs need only one byte from the first cache line.
	// The full classifier remains authoritative whenever any tuple/QFI/UE
	// constraint is present.
	if len(info.SdfFilter) == 0 && len(info.QFIs) == 0 && info.UEIPv4 == nil && info.UEIPv6 == nil {
		entry.MatchMode = 1
		if info.SourceInterfacePresent && info.SourceInterface <= 1 {
			entry.MatchMode = info.SourceInterface + 2
		} else if info.SourceInterfacePresent {
			entry.MatchMode = 0
		}
	}
	entry.ReturnPdr.FarId = info.ReturnFarID
	entry.ReturnPdr.QerCount = uint8(len(info.ReturnQerIDs))
	copy(entry.ReturnPdr.QerId[:], info.ReturnQerIDs)
	if info.ReturnNR {
		entry.ReturnNrFlag = 1
	}
	if info.OuterHeaderRemovalPresent {
		entry.Pdr.OuterHeaderRemovalPresent = 1
	}
	entry.Pdr.OuterHeaderRemoval, entry.Pdr.FarId = info.OuterHeaderRemoval, info.FarId
	entry.Pdr.QerCount = uint8(len(info.QerIDs))
	copy(entry.Pdr.QerId[:], info.QerIDs)
	for _, id := range info.QerIDs {
		if id == 0 {
			return entry, fmt.Errorf("reserved QER slot 0")
		}
	}
	for _, id := range info.UrrIDs {
		if id == 0 {
			return entry, fmt.Errorf("reserved URR slot 0")
		}
	}
	copy(entry.Pdr.UrrId[:], info.UrrIDs)
	if info.TraceFlag {
		entry.TraceFlag = 1
	}
	if info.NRFlag {
		entry.NrFlag = 1
	}
	if info.NotifyFlag {
		entry.Notify = 1
	}
	if info.UEDestination {
		entry.UeDestination = 1
	}
	if info.SourceInterfacePresent {
		entry.SourceInterfacePresent = 1
		entry.SourceInterface = info.SourceInterface
	}
	if info.UEIPv4 != nil {
		ip := info.UEIPv4.To4()
		if ip == nil {
			return entry, fmt.Errorf("invalid PDI IPv4 address")
		}
		entry.UeIp4Present = 1
		entry.UeIp4 = binary.LittleEndian.Uint32(ip)
		entry.UeMask4 = ^uint32(0)
	}
	if info.UEIPv6 != nil {
		ip := info.UEIPv6.To16()
		if ip == nil {
			return entry, fmt.Errorf("invalid PDI IPv6 address")
		}
		entry.UeIp6Present = 1
		copy(entry.UeIp6[:], ip)
		mask := info.UEIPv6Mask
		if mask == nil {
			mask = net.CIDRMask(128, 128)
		}
		if len(mask) != 16 {
			return entry, fmt.Errorf("invalid PDI IPv6 mask")
		}
		copy(entry.UeMask6[:], mask)
	}
	if ip := info.AssignedIPv4.To4(); ip != nil {
		entry.AssignedIp4Present = 1
		entry.AssignedIp4 = binary.LittleEndian.Uint32(ip)
	}
	if ip := info.AssignedIPv6.To16(); ip != nil && info.AssignedIPv6.To4() == nil {
		entry.AssignedIp6Present = 1
		copy(entry.AssignedIp6[:], ip)
		mask := info.AssignedIPv6Mask
		if mask == nil {
			mask = net.CIDRMask(128, 128)
		}
		if len(mask) != 16 {
			return entry, fmt.Errorf("invalid assigned IPv6 mask")
		}
		copy(entry.AssignedMask6[:], mask)
	}
	entry.QfiCount = uint8(len(info.QFIs))
	copy(entry.Qfis[:], info.QFIs)
	entry.SdfCount = uint8(len(info.SdfFilter))
	for i, source := range info.SdfFilter {
		target := &entry.SdfFilters[i]
		target.Protocol = source.Protocol
		if source.PortsPresent {
			target.PortsPresent = 1
		}
		target.SrcAddr.Type = source.SrcAddress.Type
		target.SrcAddr.Ip = Copy16Ip(source.SrcAddress.Ip)
		target.SrcAddr.Mask = Copy16Ip(source.SrcAddress.Mask)
		target.DstAddr.Type = source.DstAddress.Type
		target.DstAddr.Ip = Copy16Ip(source.DstAddress.Ip)
		target.DstAddr.Mask = Copy16Ip(source.DstAddress.Mask)
		target.SrcPort.LowerBound = source.SrcPortRange.LowerBound
		target.SrcPort.UpperBound = source.SrcPortRange.UpperBound
		target.DstPort.LowerBound = source.DstPortRange.LowerBound
		target.DstPort.UpperBound = source.DstPortRange.UpperBound
	}
	return entry, nil
}

// DecodePDRBucket returns the ordered, occupied rules for diagnostics.
func DecodePDRBucket(bucket IpEntrypointPdrInfo) []PdrInfo {
	count := int(min(bucket.Count, uint32(MaxPDRsPerKey)))
	result := make([]PdrInfo, 0, count)
	for _, entry := range bucket.Entries[:count] {
		info := PdrInfo{ReturnFarID: entry.ReturnPdr.FarId, ReturnQerIDs: append([]uint32(nil), entry.ReturnPdr.QerId[:min(int(entry.ReturnPdr.QerCount), MaxQERsPerPDR)]...), ReturnNR: entry.ReturnNrFlag != 0, SessionID: bucket.SessionId, PdrID: entry.PdrId, Precedence: entry.Precedence, FarId: entry.Pdr.FarId, QerIDs: append([]uint32(nil), entry.Pdr.QerId[:min(int(entry.Pdr.QerCount), MaxQERsPerPDR)]...), OuterHeaderRemoval: entry.Pdr.OuterHeaderRemoval, OuterHeaderRemovalPresent: entry.Pdr.OuterHeaderRemovalPresent != 0, TraceFlag: entry.TraceFlag != 0, NRFlag: entry.NrFlag != 0, NotifyFlag: entry.Notify != 0, SourceInterfacePresent: entry.SourceInterfacePresent != 0, SourceInterface: entry.SourceInterface, UEDestination: entry.UeDestination != 0}
		for _, id := range entry.Pdr.UrrId {
			if id != 0 {
				info.UrrIDs = append(info.UrrIDs, id)
			}
		}
		info.QFIs = append([]uint8(nil), entry.Qfis[:min(int(entry.QfiCount), MaxQFIsPerPDR)]...)
		if entry.UeIp4Present != 0 {
			info.UEIPv4 = make(net.IP, 4)
			binary.LittleEndian.PutUint32(info.UEIPv4, entry.UeIp4)
		}
		if entry.UeIp6Present != 0 {
			info.UEIPv6 = append(net.IP(nil), entry.UeIp6[:]...)
			info.UEIPv6Mask = append(net.IPMask(nil), entry.UeMask6[:]...)
		}
		if entry.AssignedIp4Present != 0 {
			info.AssignedIPv4 = make(net.IP, 4)
			binary.LittleEndian.PutUint32(info.AssignedIPv4, entry.AssignedIp4)
		}
		if entry.AssignedIp6Present != 0 {
			info.AssignedIPv6 = append(net.IP(nil), entry.AssignedIp6[:]...)
			info.AssignedIPv6Mask = append(net.IPMask(nil), entry.AssignedMask6[:]...)
		}
		for _, filter := range entry.SdfFilters[:min(int(entry.SdfCount), MaxSDFFiltersPerPDR)] {
			info.SdfFilter = append(info.SdfFilter, SdfFilter{Protocol: filter.Protocol, SrcAddress: decodeSubnet(filter.SrcAddr.Type, filter.SrcAddr.Ip, filter.SrcAddr.Mask), DstAddress: decodeSubnet(filter.DstAddr.Type, filter.DstAddr.Ip, filter.DstAddr.Mask), SrcPortRange: PortRange{filter.SrcPort.LowerBound, filter.SrcPort.UpperBound}, DstPortRange: PortRange{filter.DstPort.LowerBound, filter.DstPort.UpperBound}})
		}
		result = append(result, info)
	}
	return result
}
func decodeSubnet(kind uint8, ip, mask [16]byte) IpWMask {
	if kind == 0 || kind == 3 {
		return IpWMask{Type: kind}
	}
	size := 16
	if kind == 1 {
		size = 4
	}
	result := IpWMask{Type: kind, Ip: make(net.IP, size), Mask: make(net.IPMask, size)}
	for i := 0; i < size; i++ {
		result.Ip[i] = ip[size-1-i]
		result.Mask[i] = mask[size-1-i]
	}
	return result
}

func Copy16Ip[T ~[]byte](arr T) [16]byte {
	const Ipv4len = 4
	const Ipv6len = 16
	var c [Ipv6len]byte
	var arrLen int
	if len(arr) == Ipv4len {
		arrLen = Ipv4len
	} else if len(arr) == Ipv6len {
		arrLen = Ipv6len
	} else if len(arr) == 0 || arr == nil {
		return c
	}
	for i := 0; i < arrLen; i++ {
		c[i] = (arr)[arrLen-1-i]
	}
	return c
}

func (sdfFilter *SdfFilter) String() string {
	return fmt.Sprintf("%+v", *sdfFilter)
}

func (b *BpfObjects) downlinkMap(ip net.IP) (*ebpf.Map, interface{}, error) {
	return b.downlinkRuleMap(ip, nil)
}
func (b *BpfObjects) downlinkRuleMap(ip net.IP, mask net.IPMask) (*ebpf.Map, interface{}, error) {
	if address := ip.To4(); address != nil {
		var key [4]byte
		copy(key[:], address)
		return b.PdrMapDownlinkIp4, key, nil
	}
	if ip = ip.To16(); ip == nil {
		return nil, nil, fmt.Errorf("invalid PDR address")
	}
	prefix := 128
	if mask != nil {
		ones, bits := mask.Size()
		if bits != 128 {
			return nil, nil, fmt.Errorf("invalid IPv6 prefix mask")
		}
		prefix = ones
		ip = ip.Mask(mask)
	}
	key := IpEntrypointIpv6PdrKey{PrefixLength: uint32(prefix)}
	copy(key.Address[:], ip)
	return b.PdrMapDownlinkIp6, key, nil
}

// LookupDownlinkPDR selects the longest matching IPv6 prefix or an exact IPv4 key.
func (b *BpfObjects) LookupDownlinkPDR(ip net.IP) (IpEntrypointPdrInfo, error) {
	var bucket IpEntrypointPdrInfo
	m, key, err := b.downlinkMap(ip)
	if err != nil {
		return bucket, err
	}
	err = m.Lookup(key, &bucket)
	return bucket, err
}
func (b *BpfObjects) checkIPv6Overlap(key IpEntrypointIpv6PdrKey, owner uint64) error {
	var existing IpEntrypointIpv6PdrKey
	var value IpEntrypointPdrInfo
	iter := b.PdrMapDownlinkIp6.Iterate()
	for iter.Next(&existing, &value) {
		if existing == key {
			continue
		}
		bits := min(int(existing.PrefixLength), int(key.PrefixLength))
		mask := net.CIDRMask(bits, 128)
		if net.IP(existing.Address[:]).Mask(mask).Equal(net.IP(key.Address[:]).Mask(mask)) {
			if value.SessionId != owner {
				return ErrKeyOwned
			}
			return fmt.Errorf("overlapping distinct IPv6 prefixes: %w", ErrUnsupportedRuleContent)
		}
	}
	return iter.Err()
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func qerMapValue(info QerInfo) IpEntrypointQerInfo {
	return IpEntrypointQerInfo{UlGateStatus: info.GateStatusUL, DlGateStatus: info.GateStatusDL, Qfi: info.Qfi, QfiPresent: boolByte(info.QFIPresent), Rqi: info.RQI, Dscp: info.Dscp, UlMaximumBitrate: info.MaxBitrateUL, DlMaximumBitrate: info.MaxBitrateDL}
}

// ResetUrr resets a retained counter only after its final PDR is detached.
// Callers must quiesce rule users through a RuleTransaction.
func (b *BpfObjects) ResetUrr(id uint32) error {
	if id == 0 {
		return fmt.Errorf("reserved URR slot")
	}
	return b.UrrMap.Put(id, &IpEntrypointUrrInfo{})
}

// lookupRuleValue requires an exact rule key. LPM lookup may otherwise return a
// covering prefix during make-before-break, which is a distinct map entry.
func lookupRuleValue(m *ebpf.Map, key, value interface{}) error {
	if err := m.Lookup(key, value); err != nil {
		return err
	}
	prefix, ok := key.(IpEntrypointIpv6PdrKey)
	if !ok {
		return nil
	}
	bucket, ok := value.(*IpEntrypointPdrInfo)
	if !ok || bucket.Count == 0 {
		return ebpf.ErrKeyNotExist
	}
	bits, _ := net.IPMask(bucket.Entries[0].UeMask6[:]).Size()
	if uint32(bits) != prefix.PrefixLength {
		*bucket = IpEntrypointPdrInfo{}
		return ebpf.ErrKeyNotExist
	}
	return nil
}
