package core

import (
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

type reportedUsage struct {
	id, globalID     uint32
	uplink, downlink uint64
}
type reportCleanup struct {
	association    *NodeAssociation
	session        *Session
	failedAt, next time.Time
}

// bindReportUsageLocked retains the octets admitted to reliable delivery. A
// failed transfer returns them to that URR's next report (TS 29.244 V20.1.0
// clauses 6.3.5.2 and 6.4), independently of subsequent counter resets.
func (conn *PfcpConnection) bindReportUsageLocked(msg message.Message, assoc *NodeAssociation, seid uint64) {
	report, ok := msg.(*message.SessionReportRequest)
	if !ok || assoc == nil || assoc.Sessions[seid] == nil {
		return
	}
	var usage []reportedUsage
	for _, item := range report.UsageReport {
		fields, err := item.UsageReportWithinSessionReportRequest()
		if err != nil {
			continue
		}
		id, err := fields.URRID.URRID()
		if err != nil {
			continue
		}
		volume, err := fields.VolumeMeasurement.VolumeMeasurement()
		if err != nil {
			continue
		}
		urr, ok := assoc.Sessions[seid].URRs[id]
		if !ok {
			continue
		}
		usage = append(usage, reportedUsage{id, urr.GlobalId, volume.UplinkVolume, volume.DownlinkVolume})
	}
	conn.transport.mu.Lock()
	if req := conn.transport.pending[msg.Sequence()]; req != nil {
		req.usage = usage
	}
	conn.transport.mu.Unlock()
}

func (conn *PfcpConnection) completeReportLocked(req *pendingRequest, session *Session, result requestResult) {
	if result.outcome == requestAccepted {
		return
	} // Clause 6.3.5.2: delivered.
	if response, ok := result.response.(*message.SessionReportResponse); ok {
		if cause, err := response.Cause.Cause(); err == nil && cause == ie.CauseSessionContextNotFound {
			// Clause 6.3.5.3: the CP has no corresponding context. Queue local
			// deletion; the completion callback never waits for kernel reclamation.
			conn.reportCleanup = append(conn.reportCleanup, reportCleanup{association: req.association, session: session})
			log.Warn().Uint64("session", session.LocalSEID).Msg("CP has no session context; schedule local rule cleanup")
			return
		}
	}
	for _, usage := range req.usage {
		urr, ok := session.URRs[usage.id]
		if !ok || urr.GlobalId != usage.globalID {
			PfcpUndeliveredUsage.Add(float64(usage.uplink + usage.downlink))
			log.Error().Uint64("session", session.LocalSEID).Uint32("urr", usage.id).Uint64("uplink", usage.uplink).Uint64("downlink", usage.downlink).Msg("Failed report belongs to a removed or replaced URR; octets cannot be merged into another rule")
			continue
		}
		urr.UnreportedUplink += usage.uplink
		urr.UnreportedDownlink += usage.downlink
		urr.UrrInfo.VolumeReported = false
		session.URRs[usage.id] = urr
	}
}

func (conn *PfcpConnection) serviceReportCleanupLocked(now time.Time) {
	pending := conn.reportCleanup
	conn.reportCleanup = nil
	for _, work := range pending {
		assoc, session := work.association, work.session
		if conn.associationByID(assoc.ID) != assoc || assoc.Sessions[session.LocalSEID] != session {
			continue
		}
		if now.Before(work.next) {
			conn.reportCleanup = append(conn.reportCleanup, work)
			continue
		}
		if err := conn.DeleteSession(session); err != nil {
			if work.failedAt.IsZero() {
				work.failedAt = time.Now()
			}
			if now.Sub(work.failedAt) >= AssociationCleanupTimeout {
				assoc.cleanupError = err
				conn.cleanupFailedLocked(assoc)
			} else {
				work.next = time.Now().Add(100 * time.Millisecond)
				conn.reportCleanup = append(conn.reportCleanup, work)
			}
			log.Error().Err(err).Uint64("session", session.LocalSEID).Msg("Retry local deletion after CP context-not-found")
		} else {
			conn.forgetSession(assoc, session.LocalSEID)
		}
	}
}

func recordUndeliveredUsage(request *pendingRequest, reason string) {
	for _, usage := range request.usage {
		PfcpUndeliveredUsage.Add(float64(usage.uplink + usage.downlink))
		log.Error().Uint64("session", request.localSEID).Uint32("urr", usage.id).Uint64("uplink", usage.uplink).Uint64("downlink", usage.downlink).Str("reason", reason).Msg("Failed report outlived its local context; octets cannot be merged into another rule")
	}
}
