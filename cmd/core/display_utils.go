// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

func writeLineTabbed(sb *strings.Builder, s string, tab int) {
	sb.WriteString(strings.Repeat("  ", tab))
	sb.WriteString(s)
	sb.WriteString("\n")
}

func printAssociationSetupRequest(req *message.AssociationSetupRequest) {
	var sb strings.Builder
	sb.WriteString("\n")
	writeLineTabbed(&sb, "Association Setup Request:", 0)
	nodeId, err := req.NodeID.NodeID()
	if err == nil {
		writeLineTabbed(&sb, fmt.Sprintf("Node ID: %s", nodeIDText(nodeId)), 1)
	}
	if req.RecoveryTimeStamp != nil {
		recoveryTime, err := req.RecoveryTimeStamp.RecoveryTimeStamp()
		if err == nil {
			writeLineTabbed(&sb, fmt.Sprintf("Recovery Time: %s", recoveryTime.String()), 1)
		}
	}
	log.Info().Msg(sb.String())
}

func printAssociationUpdateRequest(req *message.AssociationUpdateRequest) {
	var sb strings.Builder
	sb.WriteString("\n")
	writeLineTabbed(&sb, "Association Update Request:", 0)
	nodeId, err := req.NodeID.NodeID()
	if err == nil {
		writeLineTabbed(&sb, fmt.Sprintf("Node ID: %s", nodeIDText(nodeId)), 1)
	}
	log.Info().Msg(sb.String())
}

func GetFSEID(CPFSEID *ie.IE) uint64 {
	if CPFSEID != nil {
		if fseid, err := CPFSEID.FSEID(); err == nil {
			return fseid.SEID
		}
	}
	return 0
}

func printSessionEstablishmentRequest(req *message.SessionEstablishmentRequest, profile PfcpProfile) {
	var sb strings.Builder
	sb.WriteString("\n")
	writeLineTabbed(&sb, fmt.Sprintf("%s( SEID: %#016x, F-SEID: %#016x ):", req.MessageTypeName(), req.SEID(), GetFSEID(req.CPFSEID)), 0)

	for _, pdr := range req.CreatePDR {
		sb.WriteString("  Create")
		displayPdr(&sb, pdr)
	}

	for _, far := range req.CreateFAR {
		sb.WriteString("  Create")
		displayFar(&sb, far, profile)
	}

	for _, qer := range req.CreateQER {
		sb.WriteString("  Create")
		displayQer(&sb, qer, profile)
	}

	for _, urr := range req.CreateURR {
		sb.WriteString("  Create")
		displayUrr(&sb, urr)
	}

	if req.CreateBAR != nil {
		sb.WriteString("  Create")
		displayBar(&sb, req.CreateBAR)
	}

	if imsi, msisdn := profile.ParseSubscriberData(req.OtherIEs); imsi != "" || msisdn != "" {
		if imsi != "" {
			writeLineTabbed(&sb, fmt.Sprintf("IMSI: %s ", imsi), 1)
		}
		if msisdn != "" {
			writeLineTabbed(&sb, fmt.Sprintf("MSISDN: %s ", msisdn), 1)
		}
	}

	if req.UserID != nil {
		if userID, err := req.UserID.UserID(); err == nil {
			if (userID.Flags & 0x01) == 0x01 {
				writeLineTabbed(&sb, fmt.Sprintf("IMSI: %s ", userID.IMSI), 1)
			}

			if (userID.Flags & 0x02) == 0x02 {
				writeLineTabbed(&sb, fmt.Sprintf("IMEI: %s ", userID.IMEI), 1)
			}

			if (userID.Flags & 0x04) == 0x04 {
				writeLineTabbed(&sb, fmt.Sprintf("MSISDN: %s ", userID.MSISDN), 1)
			}
		}
	}

	if req.APNDNN != nil {
		if apn, err := req.APNDNN.APNDNN(); err == nil {
			writeLineTabbed(&sb, fmt.Sprintf("APN/DNN: %s ", apn), 1)
		}
	}

	if req.SNSSAI != nil {
		if snssai, err := req.SNSSAI.SNSSAI(); err == nil && len(snssai) == 4 {
			writeLineTabbed(&sb, fmt.Sprintf("S-NSSAI: SST: %d SD: %x ", snssai[0], snssai[1:3]), 1)
		}
	}

	log.Debug().Msg(sb.String())
}

// IE Contents of Create/Update/Remove are mostly the same
func printSessionModificationRequest(req *message.SessionModificationRequest, profile PfcpProfile) {
	var sb strings.Builder
	sb.WriteString("\n")
	writeLineTabbed(&sb, fmt.Sprintf("%s( SEID: %#016x, F-SEID: %#016x ):", req.MessageTypeName(), req.SEID(), GetFSEID(req.CPFSEID)), 0)
	for _, pdr := range req.CreatePDR {
		sb.WriteString("  Create")
		displayPdr(&sb, pdr)
	}

	for _, far := range req.CreateFAR {
		sb.WriteString("  Create")
		displayFar(&sb, far, profile)
	}

	for _, qer := range req.CreateQER {
		sb.WriteString("  Create")
		displayQer(&sb, qer, profile)
	}

	for _, urr := range req.CreateURR {
		sb.WriteString("  Create")
		displayUrr(&sb, urr)
	}

	if req.CreateBAR != nil {
		sb.WriteString("  Create")
		displayBar(&sb, req.CreateBAR)
	}

	for _, pdr := range req.UpdatePDR {
		sb.WriteString("  Update")
		displayPdr(&sb, pdr)
	}

	for _, far := range req.UpdateFAR {
		sb.WriteString("  Update")
		displayFar(&sb, far, profile)
	}

	for _, qer := range req.UpdateQER {
		sb.WriteString("  Update")
		displayQer(&sb, qer, profile)
	}

	for _, urr := range req.UpdateURR {
		sb.WriteString("  Update")
		displayUrr(&sb, urr)
	}

	if req.UpdateBAR != nil {
		updateBAR, err := req.UpdateBAR.UpdateBARWithinSessionModificationRequest()
		if err != nil {
			return
		}
		writeLineTabbed(&sb, "Update BAR:", 1)
		barId, err := updateBAR.BARID.BARID()
		if err == nil {
			writeLineTabbed(&sb, fmt.Sprintf("BAR ID: %d ", barId), 2)
		}
		downlink, err := updateBAR.DownlinkDataNotificationDelay.DownlinkDataNotificationDelay()
		if err == nil {
			writeLineTabbed(&sb, fmt.Sprintf("Downlink Data Notification Delay: %s ", downlink), 2)
		}
		suggestedBufferingPackets, err := updateBAR.SuggestedBufferingPacketsCount.SuggestedBufferingPacketsCount()
		if err == nil {
			writeLineTabbed(&sb, fmt.Sprintf("Suggested Buffering Packets Count: %d ", suggestedBufferingPackets), 2)
		}
		mtEdtControl, err := updateBAR.MTEDTControlInformation.MTEDTControlInformation()
		if err == nil {
			writeLineTabbed(&sb, fmt.Sprintf("MT EDI: %d ", mtEdtControl), 2)
		}
	}

	//log.Println("------ Remove:")
	for _, pdr := range req.RemovePDR {
		sb.WriteString("  Remove")
		displayPdr(&sb, pdr)
	}

	for _, far := range req.RemoveFAR {
		sb.WriteString("  Remove")
		displayFar(&sb, far, profile)
	}

	for _, qer := range req.RemoveQER {
		sb.WriteString("  Remove")
		displayQer(&sb, qer, profile)
	}

	for _, urr := range req.RemoveURR {
		sb.WriteString("  Remove")
		displayUrr(&sb, urr)
	}

	if req.RemoveBAR != nil {
		removeBAR, err := req.RemoveBAR.RemoveBAR()
		if err != nil {
			return
		}
		writeLineTabbed(&sb, "Remove BAR:", 1)
		barId, err := removeBAR.BARID.BARID()
		if err == nil {
			writeLineTabbed(&sb, fmt.Sprintf("BAR ID: %d ", barId), 2)
		}
	}

	if imsi, msisdn := profile.ParseSubscriberData(req.OtherIEs); imsi != "" || msisdn != "" {
		if imsi != "" {
			writeLineTabbed(&sb, fmt.Sprintf("IMSI: %s ", imsi), 1)
		}
		if msisdn != "" {
			writeLineTabbed(&sb, fmt.Sprintf("MSISDN: %s ", msisdn), 1)
		}
	}

	log.Debug().Msg(sb.String())
}

func printSessionDeleteRequest(req *message.SessionDeletionRequest) {
	var sb strings.Builder
	sb.WriteString("\n")
	writeLineTabbed(&sb, fmt.Sprintf("%s( SEID: %#016x, F-SEID: %#016x ):", req.MessageTypeName(), req.SEID(), 0), 0)
	log.Debug().Msg(sb.String())
}

func displayBar(sb *strings.Builder, bar *ie.IE) {
	var fieldBARID, fieldDownlinkDataNotificationDelay, fieldSuggestedBufferingPacketsCount, fieldMTEDTControlInformation *ie.IE
	switch bar.Type {
	case ie.CreateBAR:
		f, err := bar.CreateBAR()
		if err != nil {
			return
		}
		fieldBARID, fieldDownlinkDataNotificationDelay, fieldMTEDTControlInformation = f.BARID, f.DownlinkDataNotificationDelay, f.MTEDTControlInformation
	case ie.UpdateBARWithinSessionModificationRequest:
		f, err := bar.UpdateBARWithinSessionModificationRequest()
		if err != nil {
			return
		}
		fieldBARID, fieldDownlinkDataNotificationDelay, fieldSuggestedBufferingPacketsCount, fieldMTEDTControlInformation = f.BARID, f.DownlinkDataNotificationDelay, f.SuggestedBufferingPacketsCount, f.MTEDTControlInformation
	case ie.RemoveBAR:
		f, err := bar.RemoveBAR()
		if err != nil {
			return
		}
		fieldBARID = f.BARID
	default:
		return
	}

	barId, _ := fieldBARID.BARID()
	fmt.Fprintf(sb, "BAR ID: %d\n", barId)

	downlink, err := fieldDownlinkDataNotificationDelay.DownlinkDataNotificationDelay()
	if err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Downlink Data Notification Delay: %s ", downlink), 2)
	}
	suggestedBufferingPackets, err := fieldSuggestedBufferingPacketsCount.SuggestedBufferingPacketsCount()
	if err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Suggested Buffering Packets Count: %d ", suggestedBufferingPackets), 2)
	}
	mtEdtControl, err := fieldMTEDTControlInformation.MTEDTControlInformation()
	if err == nil {
		writeLineTabbed(sb, fmt.Sprintf("MT EDI: %d ", mtEdtControl), 2)
	}
}

func displayUrr(sb *strings.Builder, urr *ie.IE) {
	var fieldURRID, fieldMeasurementMethod, fieldVolumeThreshold, fieldTimeThreshold, fieldMonitoringTime *ie.IE
	switch urr.Type {
	case ie.CreateURR:
		f, err := urr.CreateURR()
		if err != nil {
			return
		}
		fieldURRID, fieldMeasurementMethod, fieldVolumeThreshold, fieldTimeThreshold, fieldMonitoringTime = f.URRID, f.MeasurementMethod, f.VolumeThreshold, f.TimeThreshold, f.MonitoringTime
	case ie.UpdateURR:
		f, err := urr.UpdateURR()
		if err != nil {
			return
		}
		fieldURRID, fieldMeasurementMethod, fieldVolumeThreshold, fieldTimeThreshold, fieldMonitoringTime = f.URRID, f.MeasurementMethod, f.VolumeThreshold, f.TimeThreshold, f.MonitoringTime
	case ie.RemoveURR:
		f, err := urr.RemoveURR()
		if err != nil {
			return
		}
		fieldURRID = f.URRID
	default:
		return
	}

	urrId, _ := fieldURRID.URRID()
	fmt.Fprintf(sb, "URR ID: %d \n", urrId)

	if measurementMethod, err := fieldMeasurementMethod.MeasurementMethod(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Measurement Method: %d ", measurementMethod), 2)
	}
	if volumeThreshold, err := fieldVolumeThreshold.VolumeThreshold(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Volume Threshold: %+v ", volumeThreshold), 2)
	}
	if timeThreshold, err := fieldTimeThreshold.TimeThreshold(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Time Threshold: %f s", timeThreshold.Seconds()), 2)
	}
	if monitoringTime, err := fieldMonitoringTime.MonitoringTime(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Monitoring Time: %s ", monitoringTime.Format(time.RFC3339)), 2)
	}
}

func displayQer(sb *strings.Builder, qer *ie.IE, profile PfcpProfile) {
	var fieldQERID, fieldGateStatus, fieldMBR *ie.IE
	switch qer.Type {
	case ie.CreateQER:
		f, err := qer.CreateQER()
		if err != nil {
			return
		}
		fieldQERID, fieldGateStatus, fieldMBR = f.QERID, f.GateStatus, f.MaximumBitrate
	case ie.UpdateQER:
		f, err := qer.UpdateQER()
		if err != nil {
			return
		}
		fieldQERID, fieldGateStatus, fieldMBR = f.QERID, f.GateStatus, f.MaximumBitrate
	case ie.RemoveQER:
		f, err := qer.RemoveQER()
		if err != nil {
			return
		}
		fieldQERID = f.QERID
	default:
		return
	}

	qerId, _ := fieldQERID.QERID()
	fmt.Fprintf(sb, "QER ID: %d \n", qerId)

	if gateStatusDL, err := fieldGateStatus.GateStatusDL(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Gate Status DL: %d ", gateStatusDL), 2)
	}
	if gateStatusUL, err := fieldGateStatus.GateStatusUL(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Gate Status UL: %d ", gateStatusUL), 2)
	}
	if maxBitrateDL, err := fieldMBR.MBRDL(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Max Bitrate DL: %d ", uint32(maxBitrateDL)), 2)
	}
	if maxBitrateUL, err := fieldMBR.MBRUL(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Max Bitrate UL: %d ", uint32(maxBitrateUL)), 2)
	}
	if qfi, ok := profile.ParseQFI(qer); ok {
		writeLineTabbed(sb, fmt.Sprintf("QFI: %d ", qfi), 2)
	}
}

func displayFar(sb *strings.Builder, far *ie.IE, profile PfcpProfile) {
	var id, action, bar, forwardIE *ie.IE
	var update bool
	switch far.Type {
	case ie.CreateFAR:
		f, err := far.CreateFAR()
		if err != nil {
			return
		}
		id, action, bar, forwardIE = f.FARID, f.ApplyAction, f.BARID, f.ForwardingParameters
	case ie.UpdateFAR:
		f, err := far.UpdateFAR()
		if err != nil {
			return
		}
		id, action, bar, forwardIE = f.FARID, f.ApplyAction, f.BARID, f.UpdateForwardingParameters
		update = true
	case ie.RemoveFAR:
		f, err := far.RemoveFAR()
		if err != nil {
			return
		}
		id = f.FARID
	default:
		return
	}
	farId, _ := id.FARID()
	fmt.Fprintf(sb, "FAR ID: %d \n", farId)

	applyAction, err := action.ApplyAction()
	if err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Apply Action: %+v ", applyAction), 2)
	}
	var network, outer, redirect, enrichment, marking *ie.IE
	if forwardIE != nil {
		if update {
			f, err := forwardIE.UpdateForwardingParameters()
			if err != nil {
				return
			}
			network, outer, redirect, enrichment, marking = f.NetworkInstance, f.OuterHeaderCreation, f.RedirectInformation, f.HeaderEnrichment, f.TransportLevelMarking
		} else {
			f, err := forwardIE.ForwardingParameters()
			if err != nil {
				return
			}
			network, outer, redirect, enrichment, marking = f.NetworkInstance, f.OuterHeaderCreation, f.RedirectInformation, f.HeaderEnrichment, f.TransportLevelMarking
		}
		if value, err := network.NetworkInstance(); err == nil {
			writeLineTabbed(sb, fmt.Sprintf("Network Instance: %s", value), 3)
		}
		if outer != nil {
			if f, err := profile.ParseOuterHeaderCreation(outer); err == nil {
				writeLineTabbed(sb, fmt.Sprintf("Outer Header Creation: description=%d teid=%d ipv4=%v ipv6=%v port=%d ctag=%d stag=%d", f.Description, f.Teid, f.IPv4Address, f.IPv6Address, f.PortNumber, f.CTag, f.STag), 3)
			}
		}
		if value, err := redirect.RedirectInformation(); err == nil {
			writeLineTabbed(sb, fmt.Sprintf("Redirect Information: %s %s", value.RedirectServerAddress, value.OtherRedirectServerAddress), 3)
		}
		if value, err := enrichment.HeaderEnrichment(); err == nil {
			writeLineTabbed(sb, fmt.Sprintf("Header Enrichment: %s : %s", value.HeaderFieldName, value.HeaderFieldValue), 3)
		}
	}
	barId, err := bar.BARID()
	if err == nil {
		writeLineTabbed(sb, fmt.Sprintf("BAR ID: %d ", barId), 2)
	}
	transportLevelMarking, err := marking.TransportLevelMarking()
	if err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Transport Level Marking: %d", transportLevelMarking), 2)
		// DSCP (first octet) and ToS or Traffic Class mask (second octet)
		buf := transportLevelMarking
		writeLineTabbed(sb, fmt.Sprintf("DSCP: %x", buf[0]), 3)
		writeLineTabbed(sb, fmt.Sprintf("ToS or Traffic Class mask: %x", buf[1]), 3)
	}
}

func displayPdr(sb *strings.Builder, pdr *ie.IE) {
	var id, removal, farID, pdiIE *ie.IE
	var qerIDs, urrIDs []*ie.IE
	switch pdr.Type {
	case ie.CreatePDR:
		f, err := pdr.CreatePDR()
		if err != nil {
			return
		}
		id, removal, farID, pdiIE, qerIDs, urrIDs = f.PDRID, f.OuterHeaderRemoval, f.FARID, f.PDI, f.QERID, f.URRID
	case ie.UpdatePDR:
		f, err := pdr.UpdatePDR()
		if err != nil {
			return
		}
		id, removal, farID, pdiIE, qerIDs, urrIDs = f.PDRID, f.OuterHeaderRemoval, f.FARID, f.PDI, f.QERID, f.URRID
	case ie.RemovePDR:
		f, err := pdr.RemovePDR()
		if err != nil {
			return
		}
		id = f.PDRID
	default:
		return
	}

	pdrId, _ := id.PDRID()
	fmt.Fprintf(sb, "PDR ID: %d \n", pdrId)

	if outerHeaderRemoval, err := removal.OuterHeaderRemovalDescription(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("Outer Header Removal: %d ", outerHeaderRemoval), 2)
	}

	if farid, err := farID.FARID(); err == nil {
		writeLineTabbed(sb, fmt.Sprintf("FAR ID: %d ", farid), 2)
	}

	for _, value := range qerIDs {
		if id, err := value.QERID(); err == nil {
			writeLineTabbed(sb, fmt.Sprintf("QER ID: %d", id), 2)
		}
	}
	for _, value := range urrIDs {
		if id, err := value.URRID(); err == nil {
			writeLineTabbed(sb, fmt.Sprintf("URR ID: %d", id), 2)
		}
	}

	if pdi, err := pdiIE.PDI(); err == nil {
		for _, x := range append(append([]*ie.IE{pdi.SourceInterface, pdi.LocalFTEID, pdi.NetworkInstance}, pdi.UEIPAddress...), pdi.SDFFilter...) {
			if x == nil {
				continue
			}
			switch x.Type {
			case 20: // IE Type source interface
				srcInterface, _ := x.SourceInterface()
				writeLineTabbed(sb, fmt.Sprintf("Source Interface: %d ", srcInterface), 2)
			case 21: // IE Type F-TEID
				if fteid, err := x.FTEID(); err == nil {
					writeLineTabbed(sb, fmt.Sprintf("F-TEID: TEID: %d, IPv4: %+v, IPv6: %+v ", fteid.TEID, fteid.IPv4Address, fteid.IPv6Address), 2)
				}
			case 93: // IE Type UE IP Address
				if ueIp, _ := x.UEIPAddress(); ueIp != nil {
					if ueIp.IPv4Address != nil {
						writeLineTabbed(sb, fmt.Sprintf("UE IPv4 Address: %s ", ueIp.IPv4Address), 2)
					}
					if ueIp.IPv6Address != nil {
						writeLineTabbed(sb, fmt.Sprintf("UE IPv6 Address: %s ", ueIp.IPv6Address), 2)
					}
				}
			case 22: // IE Type Network Instance
				if ne, err := x.NetworkInstance(); err == nil {
					writeLineTabbed(sb, fmt.Sprintf("Network Instance: %s ", ne), 2)
				}

			case 23: // IE Type SDF Filter
				if sdfFilter, err := x.SDFFilter(); err == nil {
					writeLineTabbed(sb, fmt.Sprintf("SDF Filter: %s ", sdfFilter.FlowDescription), 2)
				}
			}
		}
	}
}

func printSessionReportResponse(req *message.SessionReportResponse) {
	var sb strings.Builder
	sb.WriteString("\n")
	writeLineTabbed(&sb, fmt.Sprintf("%s( SEID: %#016x, F-SEID: %#016x ):", req.MessageTypeName(), req.SEID(), GetFSEID(req.CPFSEID)), 0)

	log.Debug().Msg(sb.String())
}
