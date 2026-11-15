// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"net"
	"slices"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

type Session struct {
	activity              *sessionActivity
	activityReserved      bool
	inactivityTimer       time.Duration
	inactivityArmed       bool
	bufferControlRevision uint64
	bufferPlan            *packetBufferPlan
	buffers               *packetBufferSession
	downlink              *downlinkNotifications
	bar                   *bufferingActionRule
	barRevision           uint64
	urrGeneration         uint64
	LocalSEID             uint64
	RemoteSEID            uint64
	CPFSEIDIPv4           net.IP // TS 29.244 V20.1.0 clause 4.3.2: session request destination.
	CPFSEIDIPv6           net.IP
	IMSI                  string
	MSISDN                string
	PDRs                  map[uint32]SPDRInfo
	FARs                  map[uint32]SFarInfo
	QERs                  map[uint32]SQerInfo
	URRs                  map[uint32]SUrrInfo
	Traced                bool
	Is5G                  bool
}

func NewSession(localSEID, remoteSEID uint64, IMSI, MSISDN string, traced bool) *Session {
	return &Session{
		LocalSEID:  localSEID,
		RemoteSEID: remoteSEID,
		IMSI:       IMSI,
		MSISDN:     MSISDN,
		PDRs:       map[uint32]SPDRInfo{},
		FARs:       map[uint32]SFarInfo{},
		QERs:       map[uint32]SQerInfo{},
		URRs:       map[uint32]SUrrInfo{},
		Traced:     traced,
		Is5G:       false,
	}
}

type SPDRInfo struct {
	FARID           *uint32  `json:"far_id,omitempty"`
	QERIDs          []uint32 `json:"qer_ids,omitempty"`
	URRIDs          []uint32 `json:"urr_ids,omitempty"`
	PdrID           uint32
	PdrInfo         ebpf.PdrInfo
	Teid            uint32
	LocalFTEIDIPv4  net.IP
	Ipv4            net.IP
	Ipv6            net.IP
	NetworkInstance string
	SourceInterface uint8
	SDFUplink       bool `json:"-"`
	AllocatedTEID   bool
	AllocatedUEIP   bool
	PCCInfo         *PCCInfo
}

type PCCInfo struct {
	PCCName      string
	Notify       bool
	RawSDFFilter string
	SDFFilter    ebpf.SdfFilter
	FAR          ebpf.FarInfo
	QER          ebpf.QerInfo
}

type SFarInfo struct {
	BARID *uint8 `json:"bar_id,omitempty"`
	// TS 29.281 V19.2.0 clause 7.3.2.3 excludes N19 End Markers.
	InterfaceType        uint8
	InterfaceTypePresent bool
	FarInfo              ebpf.FarInfo
	GlobalId             uint32
}

type SQerInfo struct {
	QerInfo  ebpf.QerInfo
	GlobalId uint32
}

type SUrrInfo struct {
	// generation identifies one Create URR lifetime, across counter-slot swaps.
	// TS 29.244 V20.1.0 clause 5.2.2.3.1 retains dissociated URRs.
	generation uint64
	// TS 29.244 V20.1.0 tables 7.5.8.3-1, 7.5.5.2-1 and 7.5.7.2-1:
	// retain the measurement window and any earlier undelivered window.
	windowStart, unreportedStart         time.Time
	UnreportedUplink, UnreportedDownlink uint64
	UrrInfo                              ebpf.UrrInfo
	GlobalId                             uint32
	ReportSeqNumber                      uint32
}

func (s *Session) NewFar(id uint32, internalId uint32, farInfo ebpf.FarInfo) {
	s.FARs[id] = SFarInfo{
		FarInfo:  farInfo,
		GlobalId: internalId,
	}
}

func (s *Session) UpdateFar(id uint32, farInfo ebpf.FarInfo) {
	sFarInfo := s.FARs[id]
	sFarInfo.FarInfo = farInfo
	s.FARs[id] = sFarInfo
}

func (s *Session) GetFar(id uint32) SFarInfo {
	return s.FARs[id]
}

func (s *Session) RemoveFar(id uint32) (SFarInfo, error) {
	sFarInfo, ok := s.FARs[id]
	if !ok {
		return SFarInfo{}, ErrSessionNotFound
	}
	delete(s.FARs, id)
	return sFarInfo, nil
}

func (s *Session) NewQer(id uint32, internalId uint32, qerInfo ebpf.QerInfo) {
	s.QERs[id] = SQerInfo{
		QerInfo:  qerInfo,
		GlobalId: internalId,
	}
}

func (s *Session) UpdateQer(id uint32, qerInfo ebpf.QerInfo) {
	sQerInfo := s.QERs[id]
	sQerInfo.QerInfo = qerInfo
	s.QERs[id] = sQerInfo
}

func (s *Session) GetQer(id uint32) SQerInfo {
	return s.QERs[id]
}

func (s *Session) RemoveQer(id uint32) (SQerInfo, error) {
	sQerInfo, ok := s.QERs[id]
	if !ok {
		return SQerInfo{}, ErrSessionNotFound
	}
	delete(s.QERs, id)
	return sQerInfo, nil
}

func (s *Session) NewUrr(id uint32, internalId uint32, urrInfo ebpf.UrrInfo) {
	s.urrGeneration++
	s.URRs[id] = SUrrInfo{
		generation:  s.urrGeneration,
		windowStart: time.Now(),
		UrrInfo:     urrInfo,
		GlobalId:    internalId,
	}
}

func (urr SUrrInfo) measurementStart() time.Time {
	if !urr.unreportedStart.IsZero() && urr.unreportedStart.Before(urr.windowStart) {
		return urr.unreportedStart
	}
	return urr.windowStart
}

func (s *Session) UpdateUrr(id uint32, urrInfo ebpf.UrrInfo) {
	sUrrInfo := s.URRs[id]
	sUrrInfo.UrrInfo = urrInfo
	s.URRs[id] = sUrrInfo
}

func (s *Session) GetUrr(id uint32) SUrrInfo {
	return s.URRs[id]
}

func (s *Session) RemoveUrr(id uint32) (SUrrInfo, error) {
	sUrrInfo, ok := s.URRs[id]
	if !ok {
		return SUrrInfo{}, ErrSessionNotFound
	}
	delete(s.URRs, id)
	return sUrrInfo, nil
}

func (s *Session) PutPDR(id uint32, info SPDRInfo) {
	s.PDRs[id] = info
}

func (s *Session) GetPDR(id uint16) SPDRInfo {
	return s.PDRs[uint32(id)]
}

func (s *Session) RemovePDR(id uint32) (SPDRInfo, error) {
	sPdrInfo, ok := s.PDRs[id]
	if !ok {
		return SPDRInfo{}, ErrSessionNotFound
	}
	delete(s.PDRs, id)
	return sPdrInfo, nil
}

func (s *Session) GetSessionImsi() string {
	return s.IMSI
}

func (s *Session) GetSessionMsisdn() string {
	return s.MSISDN
}

func (s *Session) IsSessionTraced() bool {
	return s.Traced
}

// TS 29.244 V20.1.0 clause 6.3.3.3 removes rule references as well as rules.
func removeSessionRuleReferences(session *Session, kind string, ruleID, slot uint32) {
	for id, pdr := range session.PDRs {
		switch kind {
		case "far":
			if pdr.FARID != nil && *pdr.FARID == ruleID {
				pdr.FARID = nil
			}
			if pdr.PdrInfo.FarId == slot {
				pdr.PdrInfo.FarId = 0
			}
		case "qer":
			pdr.QERIDs = slices.DeleteFunc(pdr.QERIDs, func(ref uint32) bool { return ref == ruleID })
			pdr.PdrInfo.QerIDs = slices.DeleteFunc(pdr.PdrInfo.QerIDs, func(ref uint32) bool { return ref == slot })
		case "urr":
			pdr.URRIDs = slices.DeleteFunc(pdr.URRIDs, func(ref uint32) bool { return ref == ruleID })
			pdr.PdrInfo.UrrIDs = slices.DeleteFunc(pdr.PdrInfo.UrrIDs, func(ref uint32) bool { return ref == slot })
		}
		session.PDRs[id] = pdr
	}
}
