package core

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

// SessionReleaseResult describes a committed local deletion. Report delivery
// continues independently; EPFAR says whether the CP negotiated that procedure.
type SessionReleaseResult struct {
	SEID  uint64 `json:"seid"`
	EPFAR bool   `json:"epfar"`
}

type localSessionRelease struct {
	association *NodeAssociation
	session     *Session
	entity      string
	canceled    bool
	usage       *deletedSessionUsage
	ready       bool
	failure     error
	waiting     int
	debt        []reportedUsage
	reports     []*ie.IE
	next        int
	inFlight    bool
	charge      int64
	generations map[uint32]uint64
}

func associationEPFAR(assoc *NodeAssociation) bool {
	return assoc != nil && ie.NewCPFunctionFeatures(assoc.CPFeatures...).HasEPFAR() && ie.NewUPFunctionFeatures(assoc.UPFeatures...).HasEPFAR()
}

// TS 29.244 V20.1.0 clauses 5.18.2 and 8.2.119: PSDBU follows local
// deletion, not a later CP Deletion Request. Final counts follow producer grace.
// The caller owns stateMu; no network I/O happens inside this transaction.
func (conn *PfcpConnection) beginLocalSessionReleaseLocked(assoc *NodeAssociation, session *Session) (SessionReleaseResult, error) {
	charge := config.LocalReleaseContextBytes * (1 + int64(len(session.URRs)))
	limit := conn.localReleaseLimit
	if limit == 0 {
		limit = 16 << 20
	}
	if len(conn.localReleases) >= min(128, conn.originatedRequestLimit()) || charge > limit-conn.localReleaseBytes {
		return SessionReleaseResult{}, errTransactionCapacity
	}
	usage, err := conn.deleteSessionWithUsage(session)
	if err != nil {
		return SessionReleaseResult{}, err
	}
	metadata := &Session{LocalSEID: session.LocalSEID, RemoteSEID: session.RemoteSEID, CPFSEIDIPv4: cloneIP(session.CPFSEIDIPv4), CPFSEIDIPv6: cloneIP(session.CPFSEIDIPv6), Traced: session.Traced}
	entity := assoc.sessionEntities[session.LocalSEID]
	if entity == "" {
		entity = entityAddresses(session.CPFSEIDIPv4, session.CPFSEIDIPv6, assoc.Addr)
	}
	release := &localSessionRelease{association: assoc, session: metadata, entity: entity, usage: usage, ready: usage.ready == nil, charge: charge, generations: make(map[uint32]uint64, len(session.URRs))}
	for id, urr := range session.URRs {
		release.generations[id] = urr.generation
	}
	if conn.localReleases == nil {
		conn.localReleases = make(map[uint64]*localSessionRelease)
	}
	conn.localReleases[session.LocalSEID] = release
	conn.localReleaseBytes += charge
	// An earlier report owns its admitted octets until its terminal outcome.
	// Wait for those outcomes before the last PSDBU; merge only failed windows.
	conn.transport.mu.Lock()
	for _, request := range conn.transport.pending {
		if request.typ == message.MsgTypeSessionReportRequest && request.association == assoc && request.localSEID == session.LocalSEID {
			request.localRelease = release
			release.waiting++
		}
	}
	conn.transport.mu.Unlock()
	retained := conn.reportRetries[:0]
	for _, request := range conn.reportRetries {
		if request.association == assoc && request.localSEID == session.LocalSEID {
			release.retainFailedUsage(request, request.completedOutcome)
		} else {
			retained = append(retained, request)
		}
	}
	clear(conn.reportRetries[len(retained):])
	conn.reportRetries = retained
	cleanup := conn.reportCleanup[:0]
	for _, work := range conn.reportCleanup {
		if work.request.association == assoc && work.request.localSEID == session.LocalSEID {
			release.retainFailedUsage(work.request, work.request.completedOutcome)
		} else {
			cleanup = append(cleanup, work)
		}
	}
	clear(conn.reportCleanup[len(cleanup):])
	conn.reportCleanup = cleanup
	conn.forgetSession(assoc, session.LocalSEID)
	conn.indexLocalRelease(release, 1)
	delete(conn.downlinkSessions, session.LocalSEID)
	return SessionReleaseResult{SEID: session.LocalSEID, EPFAR: associationEPFAR(assoc)}, nil
}

func (conn *PfcpConnection) completeLocalReleaseRequestLocked(request *pendingRequest, result requestResult) {
	release := request.localRelease
	if !request.localReleaseReport {
		release.waiting--
		if result.outcome != requestAccepted {
			release.retainFailedUsage(request, result.outcome)
		}
		return
	}
	release.inFlight = false
	if result.outcome != requestAccepted {
		recordUndeliveredUsage(request, "local deletion report: "+string(result.outcome))
	}
	if request.localReleaseLast {
		conn.finishLocalReleaseLocked(release)
	}
}

func (release *localSessionRelease) retainFailedUsage(request *pendingRequest, outcome requestOutcome) {
	// A timeout/invalid response does not prove that the CP omitted the usage.
	// Do not issue its octets again with a new UR-SEQN during local deletion.
	// Expose the unacknowledged window instead (clauses 6.3.5.2 and 6.4).
	if outcome != requestRejected {
		recordUndeliveredUsage(request, "unacknowledged earlier report during local release")
		return
	}
	for _, usage := range request.usage {
		generation, exists := release.generations[usage.id]
		if !exists || generation != usage.generation {
			recordUndeliveredUsage(&pendingRequest{localSEID: request.localSEID, usage: []reportedUsage{usage}}, "release cannot merge another URR lifetime")
			continue
		}
		release.debt = append(release.debt, usage)
	}
}

func (conn *PfcpConnection) finishLocalReleaseLocked(release *localSessionRelease) {
	id := release.session.LocalSEID
	if conn.localReleases[id] != release {
		return
	}
	conn.indexLocalRelease(release, -1)
	delete(conn.localReleases, id)
	conn.localReleaseBytes -= release.charge
}

// Close has canceled every outstanding request. Wait outside stateMu for the
// same bounded retirement recovery before accounting for reports not yet sent.
func (conn *PfcpConnection) closeLocalSessionReleases() {
	deadline := time.Now().Add(AssociationCleanupTimeout)
	for {
		conn.serviceLocalSessionReleases()
		conn.stateMu.Lock()
		remaining := len(conn.localReleases)
		if remaining != 0 && !time.Now().Before(deadline) {
			for _, release := range conn.localReleases {
				log.Error().Uint64("session", release.session.LocalSEID).Msg("Final usage collection did not finish before shutdown; unsnapshotted octets are unknown")
				recordUndeliveredUsage(&pendingRequest{localSEID: release.session.LocalSEID, usage: release.debt}, "shutdown before final usage collection")
				PfcpReportFailures.WithLabelValues(string(requestCanceled)).Inc()
				conn.finishLocalReleaseLocked(release)
			}
			remaining = 0
		}
		conn.stateMu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func buildLocalReleaseReports(release *localSessionRelease) error {
	// The deletion transaction snapshots counters before returning their IDs.
	// Earlier rejected windows are distinct from its captured baseline debt.
	byID := make(map[uint32]*ie.IE)
	for _, report := range release.usage.reports {
		fields, err := report.UsageReportWithinSessionDeletionResponse()
		if err != nil {
			return err
		}
		id, err := fields.URRID.URRID()
		if err != nil {
			return err
		}
		byID[id] = report
	}
	for _, debt := range release.debt {
		old := byID[debt.id]
		if old == nil {
			return fmt.Errorf("release usage lost URR %d", debt.id)
		}
		fields, err := old.UsageReportWithinSessionDeletionResponse()
		if err != nil {
			return err
		}
		volume, err := fields.VolumeMeasurement.VolumeMeasurement()
		if err != nil {
			return err
		}
		volume.UplinkVolume += debt.uplink
		volume.DownlinkVolume += debt.downlink
		fields.VolumeMeasurement = ie.NewVolumeMeasurement(7, volume.UplinkVolume+volume.DownlinkVolume, volume.UplinkVolume, volume.DownlinkVolume, 0, 0, 0)
		start, err := fields.StartTime.StartTime()
		if err != nil {
			return err
		}
		if debt.start.Before(start) {
			fields.StartTime = ie.NewStartTime(debt.start)
		}
		byID[debt.id] = fields.IE()
	}
	ids := make([]uint32, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	release.reports = make([]*ie.IE, 0, len(ids))
	for _, id := range ids {
		fields, err := byID[id].UsageReportWithinSessionDeletionResponse()
		if err != nil {
			return err
		}
		volume, err := fields.VolumeMeasurement.VolumeMeasurement()
		if err != nil {
			return err
		}
		if volume.UplinkVolume == 0 && volume.DownlinkVolume == 0 {
			continue
		}
		// Clause 8.2.41: TEBUR is bit 2 of the third trigger octet.
		children := fields.IE().ChildIEs
		for i, child := range children {
			if child.Type == ie.UsageReportTrigger {
				children[i] = ie.NewUsageReportTrigger(0, 0, 2)
			}
		}
		release.reports = append(release.reports, ie.NewUsageReportWithinSessionReportRequest(children...))
	}
	return nil
}

func (conn *PfcpConnection) serviceLocalSessionReleases() {
	conn.stateMu.Lock()
	var outgoing []admittedRequest
	for _, release := range conn.localReleases {
		if release.inFlight {
			continue
		}
		if release.failure != nil {
			continue
		}
		if !release.ready {
			select {
			case err := <-release.usage.ready:
				release.ready = true
				if err != nil {
					release.failure = err
					conn.terminalError = errors.Join(conn.terminalError, fmt.Errorf("final local-release usage: %w", err))
					if conn.failures == nil {
						conn.failures = make(chan error, 1)
					}
					select {
					case conn.failures <- conn.terminalError:
					default:
					}
					log.Error().Err(err).Uint64("session", release.session.LocalSEID).Msg("Final local-release usage unavailable")
					continue
				}
			default:
				continue
			}
		}
		if release.waiting != 0 {
			continue
		}
		if release.reports == nil {
			if err := buildLocalReleaseReports(release); err != nil {
				release.failure = err
				conn.terminalError = errors.Join(conn.terminalError, err)
				if conn.failures == nil {
					conn.failures = make(chan error, 1)
				}
				select {
				case conn.failures <- conn.terminalError:
				default:
				}
				continue
			}
		}
		if release.canceled || conn.associationByID(release.association.ID) != release.association || release.association.cleaning || conn.isClosed() {
			for _, report := range release.reports[release.next:] {
				fields, _ := report.UsageReportWithinSessionReportRequest()
				volume, _ := fields.VolumeMeasurement.VolumeMeasurement()
				id, _ := fields.URRID.URRID()
				recordUndeliveredUsage(&pendingRequest{localSEID: release.session.LocalSEID, usage: []reportedUsage{{id: id, uplink: volume.UplinkVolume, downlink: volume.DownlinkVolume}}}, "association removed during local release")
			}
			conn.finishLocalReleaseLocked(release)
			continue
		}
		// Bound each datagram, and admit at most one final report per session.
		end := release.next
		size := 64
		for end < len(release.reports) && size+release.reports[end].MarshalLen() <= 16000 {
			size += release.reports[end].MarshalLen()
			end++
		}
		if end == release.next && end < len(release.reports) {
			conn.failLocalReleaseLocked(release, errors.New("individual final usage report exceeds datagram budget"))
			continue
		}
		last := end == len(release.reports)
		kind := uint8(2)
		if len(release.reports) == 0 {
			kind = 0x40
		}
		ies := []*ie.IE{ie.New(ie.ReportType, []byte{kind})}
		ies = append(ies, release.reports[release.next:end]...)
		if last {
			ies = append(ies, ie.NewPFCPSRReqFlags(1))
		}
		report := message.NewSessionReportRequest(release.session.RemoteSEID, 0, ies...)
		peer := &net.UDPAddr{IP: cloneIP(release.session.controlIP(conn)), Port: 8805}
		socket := conn.socket()
		wire, err := conn.prepareRequestContext(report, peer, release.session.Traced, socket, release.entity, release.association, release.session.LocalSEID)
		if err != nil {
			if !errors.Is(err, errTransactionCapacity) {
				conn.failLocalReleaseLocked(release, err)
			}
			continue
		}
		conn.transport.mu.Lock()
		request := conn.transport.pending[report.Sequence()]
		request.localRelease, request.localReleaseReport, request.localReleaseLast = release, true, last
		for _, item := range release.reports[release.next:end] {
			fields, _ := item.UsageReportWithinSessionReportRequest()
			volume, _ := fields.VolumeMeasurement.VolumeMeasurement()
			id, _ := fields.URRID.URRID()
			request.usage = append(request.usage, reportedUsage{id: id, uplink: volume.UplinkVolume, downlink: volume.DownlinkVolume})
		}
		conn.transport.mu.Unlock()
		release.next = end
		release.inFlight = true
		outgoing = append(outgoing, admittedRequest{wire, report.MessageType(), peer, socket, release.session.Traced})
	}
	conn.stateMu.Unlock()
	_ = conn.sendAdmitted(outgoing)
}

func (conn *PfcpConnection) failLocalReleaseLocked(release *localSessionRelease, err error) {
	release.failure = err
	conn.terminalError = errors.Join(conn.terminalError, fmt.Errorf("local release of session %d: %w", release.session.LocalSEID, err))
	log.Error().Err(err).Uint64("session", release.session.LocalSEID).Msg("Local release cannot complete")
	if conn.failures == nil {
		conn.failures = make(chan error, 1)
	}
	select {
	case conn.failures <- conn.terminalError:
	default:
	}
}

// A detached session is no longer a live context, but its CP entity still owns
// pending report delivery. Keep that address attributable until completion so
// restart observations invalidate even reports waiting for final counter grace.
// TS 29.244 V20.1.0 clause 5.8.1; TS 23.007 V19.2.0 clause 19A.
func (conn *PfcpConnection) indexLocalRelease(release *localSessionRelease, delta int) {
	conn.addressReference(release.association, release.session.CPFSEIDIPv4.String(), delta)
	conn.addressReference(release.association, release.session.CPFSEIDIPv6.String(), delta)
}
