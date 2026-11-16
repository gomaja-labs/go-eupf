package core

import (
	"errors"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

type reportedUsage struct {
	id               uint32
	generation       uint64
	start            time.Time
	uplink, downlink uint64
}
type reportCleanup struct {
	request        *pendingRequest
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
		start, err := fields.StartTime.StartTime()
		if err != nil {
			continue
		}
		usage = append(usage, reportedUsage{id, urr.generation, start, volume.UplinkVolume, volume.DownlinkVolume})
	}
	conn.transport.mu.Lock()
	if req := conn.transport.pending[msg.Sequence()]; req != nil {
		req.usage = usage
	}
	conn.transport.mu.Unlock()
}

func (conn *PfcpConnection) completeReportLocked(req *pendingRequest, session *Session, result requestResult) {
	if result.outcome == requestAccepted && req.bufferUpdate != nil {
		conn.bufferUpdates = append(conn.bufferUpdates, req.bufferUpdate)
	}
	if req.downlink != nil && !conn.downlinkNotificationCurrent(req, session) {
		return
	}
	if conn.completeDownlinkNotificationLocked(req, session, result) {
		return
	}
	if result.outcome == requestAccepted {
		return
	} // Clause 6.3.5.2: delivered.
	if !conn.reportAddressCurrent(req, session) {
		// Table 7.5.4.1-1 and clause 6.4: this is a new procedure to
		// the current CP F-SEID, preserving all originally reported IEs.
		conn.reportRetries = append(conn.reportRetries, req)
		return
	}
	if response, ok := result.response.(*message.SessionReportResponse); ok {
		if cause, err := response.Cause.Cause(); err == nil && cause == ie.CauseSessionContextNotFound {
			// Local policy: delete when the current CP has no context. Clause
			// 6.3.5.3 prescribes only the CP response, not a UP deletion. Queue
			// reclamation; the completion callback never waits for kernel reclamation.
			conn.reportCleanup = append(conn.reportCleanup, reportCleanup{request: req})
			log.Warn().Uint64("session", session.LocalSEID).Msg("CP has no session context; schedule local rule cleanup")
			return
		}
	}
	for _, usage := range req.usage {
		urr, ok := session.URRs[usage.id]
		if !ok || urr.generation != usage.generation {
			PfcpUndeliveredUsage.Add(float64(usage.uplink + usage.downlink))
			log.Error().Uint64("session", session.LocalSEID).Uint32("urr", usage.id).Uint64("uplink", usage.uplink).Uint64("downlink", usage.downlink).Msg("Failed report belongs to a removed or replaced URR; octets cannot be merged into another rule")
			continue
		}
		urr.UnreportedUplink += usage.uplink
		urr.UnreportedDownlink += usage.downlink
		if urr.unreportedStart.IsZero() || usage.start.Before(urr.unreportedStart) {
			urr.unreportedStart = usage.start
		}
		session.URRs[usage.id] = urr
	}
}

func (conn *PfcpConnection) serviceReportCleanupLocked(now time.Time) {
	pending := conn.reportCleanup
	conn.reportCleanup = nil
	for _, work := range pending {
		req := work.request
		assoc := req.association
		session := assoc.Sessions[req.localSEID]
		if conn.associationByID(assoc.ID) != assoc || session == nil {
			// A preceding item in this detached queue may already have
			// deleted the session. Preserve each rejected window exactly once
			// (TS 29.244 V20.1.0 clauses 6.3.5.2 and 6.4).
			if release := conn.localReleases[req.localSEID]; release != nil && release.association == assoc {
				release.retainFailedUsage(req, req.completedOutcome)
			} else {
				recordUndeliveredUsage(req, "context removed before report cleanup")
			}
			continue
		}
		// The CP may change after Cause 65 but before local reclamation.
		if !conn.reportAddressCurrent(req, session) {
			conn.reportRetries = append(conn.reportRetries, req)
			continue
		}
		if now.Before(work.next) {
			conn.reportCleanup = append(conn.reportCleanup, work)
			continue
		}
		if _, err := conn.beginLocalSessionReleaseLocked(assoc, session); err != nil {
			if errors.Is(err, errTransactionCapacity) {
				work.next = time.Now().Add(100 * time.Millisecond)
				conn.reportCleanup = append(conn.reportCleanup, work)
				continue
			}
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
			conn.localReleases[session.LocalSEID].retainFailedUsage(req, req.completedOutcome)
		}
	}
}

func (conn *PfcpConnection) reportAddressCurrent(req *pendingRequest, session *Session) bool {
	return req.remoteSEID == session.RemoteSEID && req.peer.IP.Equal(session.controlIP(conn))
}

// Completion can run while transport.mu is held. Queue re-origination there;
// admission and sending happen immediately after those locks are released.
func (conn *PfcpConnection) flushReportRetries() {
	conn.stateMu.Lock()
	pending := conn.reportRetries
	conn.reportRetries = nil
	var outgoing []admittedRequest
	for _, old := range pending {
		assoc := conn.associationByID(old.associationID())
		if assoc != old.association || activeAssociation(assoc) == nil || assoc.Sessions[old.localSEID] == nil {
			recordUndeliveredUsage(old, "session removed before report re-origination")
			continue
		}
		session := assoc.Sessions[old.localSEID]
		if old.downlink != nil && !conn.downlinkNotificationCurrent(old, session) {
			continue
		}
		msg, err := message.Parse(old.wire)
		if err != nil {
			// old.wire was encoded by prepareRequestContext and is immutable.
			log.Error().Err(err).Msg("Decode retained Session Report")
			conn.completeReportLocked(old, session, requestResult{outcome: requestInvalid})
			continue
		}
		report := msg.(*message.SessionReportRequest)
		report.Header.SEID = session.RemoteSEID
		peer := *old.peer
		peer.IP = append(peer.IP[:0:0], session.controlIP(conn)...)
		socket := conn.socket()
		wire, err := conn.prepareRequestContext(report, &peer, old.trace, socket, assoc.sessionEntities[old.localSEID], assoc, old.localSEID)
		if err != nil {
			conn.reportRetries = append(conn.reportRetries, old)
			continue
		}
		conn.transport.mu.Lock()
		conn.transport.pending[report.Sequence()].usage = old.usage
		conn.transport.pending[report.Sequence()].downlink = old.downlink
		conn.transport.mu.Unlock()
		outgoing = append(outgoing, admittedRequest{wire, report.MessageType(), &peer, socket, old.trace})
	}
	conn.stateMu.Unlock()
	_ = conn.sendAdmitted(outgoing)
}

func recordUndeliveredUsage(request *pendingRequest, reason string) {
	for _, usage := range request.usage {
		PfcpUndeliveredUsage.Add(float64(usage.uplink + usage.downlink))
		log.Error().Uint64("session", request.localSEID).Uint32("urr", usage.id).Uint64("uplink", usage.uplink).Uint64("downlink", usage.downlink).Str("reason", reason).Msg("Failed report outlived its local context; octets cannot be merged into another rule")
	}
}
