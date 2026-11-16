package core

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

const activityPollInterval = 100 * time.Millisecond

// One sample may perform map I/O or admit a report. Bound work under stateMu
// independently of the number of monitored sessions.
const activityPollBatchSize = 64

// stateMu owns sampling state. The controller separately serializes map closure
// and slot allocation; packet writers change only the activity map.
type sessionActivity struct {
	controller     ebpf.SessionActivityController
	slot           uint32
	last           time.Time
	previous, next *sessionActivity
	association    *NodeAssociation
	seid           uint64
	queued         bool
	sampling       bool // stateMu prevents overlapping observations of one session.
	readersMu      sync.Mutex
	readers        int
	afterReaders   func()
}

func (activity *sessionActivity) beginRead() {
	activity.readersMu.Lock()
	activity.readers++
	activity.readersMu.Unlock()
}

func (activity *sessionActivity) endRead() {
	activity.readersMu.Lock()
	activity.readers--
	var release func()
	if activity.readers == 0 {
		release, activity.afterReaders = activity.afterReaders, nil
	}
	activity.readersMu.Unlock()
	if release != nil {
		release()
	}
}

// Rule grace covers packet writers. Sampler pins also keep the slot and its
// admission reservation alive while user space reads outside stateMu.
func (activity *sessionActivity) afterReadings(release func()) {
	activity.readersMu.Lock()
	if activity.readers != 0 {
		activity.afterReaders = release
		activity.readersMu.Unlock()
		return
	}
	activity.readersMu.Unlock()
	release()
}

// TS 29.244 V20.1.0 clauses 5.11.2 and 8.2.83: a zero or null timer
// disables reporting; an updated nonzero timer rearms it without resetting age.
func (conn *PfcpConnection) stageSessionActivity(session *Session, timer *ie.IE, timerOptional bool) error {
	if timer != nil {
		value := time.Duration(0)
		var err error
		if !isNullIE(timer) {
			value, err = timer.UserPlaneInactivityTimer()
		}
		if err != nil {
			// Table 7.5.2.1-1 marks this IE optional in Establishment;
			// table 7.5.4.1-1 makes an update conditional. Clause 7.6.8
			// discards only the incorrect optional IE, not the request.
			if !timerOptional {
				return &requestIEError{ie.CauseMandatoryIEIncorrect, ie.UserPlaneInactivityTimer, err}
			}
			log.Debug().Err(err).Uint64("seid", session.LocalSEID).Msg("Discard incorrect optional inactivity timer")
		} else {
			session.inactivityTimer, session.inactivityArmed = value, value > 0
		}
	}
	if session.activity != nil || conn.inactivityReleaseTimeout == 0 && !session.inactivityArmed {
		return nil
	}
	maps := conn.mapOperations
	if proxy, ok := maps.(*sessionMapProxy); ok {
		maps = proxy.ForwardingPlaneController
	}
	controller, ok := maps.(ebpf.SessionActivityController)
	if !ok {
		return &requestIEError{ie.CauseSystemFailure, ie.UserPlaneInactivityTimer, errors.New("session activity controller is unavailable")}
	}
	slot, err := controller.NewSessionActivity()
	if err != nil {
		return &requestIEError{ie.CauseNoResourcesAvailable, ie.UserPlaneInactivityTimer, err}
	}
	session.activity = &sessionActivity{controller: controller, slot: slot, last: time.Now()}
	session.activityReserved = true
	return nil
}

func (conn *PfcpConnection) watchSessionActivity(assoc *NodeAssociation, session *Session, delta int) {
	activity := session.activity
	if delta < 0 {
		delete(conn.activitySessions, session.LocalSEID)
		delete(conn.activityDirty, session.LocalSEID)
		if activity != nil && activity.queued {
			conn.unlinkSessionActivity(activity)
		}
		conn.activityCount.Store(int64(len(conn.activitySessions)))
		return
	}
	if activity == nil {
		return
	}
	if conn.activitySessions == nil {
		conn.activitySessions = make(map[uint64]*NodeAssociation)
		conn.activityDirty = make(map[uint64]*NodeAssociation)
	}
	conn.activitySessions[session.LocalSEID], conn.activityDirty[session.LocalSEID] = assoc, assoc
	activity.association, activity.seid = assoc, session.LocalSEID
	if !activity.queued {
		conn.appendSessionActivity(activity)
	}
	conn.activityCount.Store(int64(len(conn.activitySessions)))
}

func (conn *PfcpConnection) appendSessionActivity(activity *sessionActivity) {
	activity.previous, activity.next, activity.queued = conn.activityTail, nil, true
	if conn.activityTail != nil {
		conn.activityTail.next = activity
	} else {
		conn.activityHead = activity
	}
	conn.activityTail = activity
}

func (conn *PfcpConnection) unlinkSessionActivity(activity *sessionActivity) {
	if activity.previous != nil {
		activity.previous.next = activity.next
	} else {
		conn.activityHead = activity.next
	}
	if activity.next != nil {
		activity.next.previous = activity.previous
	} else {
		conn.activityTail = activity.previous
	}
	activity.previous, activity.next, activity.queued = nil, nil, false
}

// Periodic scans run independently of receive/dispatch. Yield between batches
// so requests can acquire stateMu while a large monitored population is sampled.
func (conn *PfcpConnection) runInactivity() {
	ticker := time.NewTicker(activityPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-conn.done:
			return
		case <-ticker.C:
			for conn.serviceInactivity(time.Now()) {
				runtime.Gosched()
			}
		}
	}
}

// TS 29.244 V20.1.0 clauses 5.11.2 and 5.18.2 share the received-packet
// activity source. Sampling rounds activity time upwards, never expiring early.
func (conn *PfcpConnection) serviceInactivity(now time.Time) bool {
	return conn.sampleInactivity(now, true, 0)
}

func (conn *PfcpConnection) serviceInactivityUpdates(now time.Time, seid uint64) {
	conn.sampleInactivity(now, false, seid)
}

func (conn *PfcpConnection) sampleInactivity(now time.Time, periodic bool, priority uint64) bool {
	if conn.activityCount.Load() == 0 {
		return false
	}
	conn.stateMu.Lock()
	if conn.isClosed() {
		conn.stateMu.Unlock()
		return false
	}
	if periodic && conn.activityRemaining == 0 && !now.Before(conn.nextActivityPoll) {
		conn.activityRemaining = len(conn.activitySessions)
		conn.nextActivityPoll = now.Add(activityPollInterval)
	}
	type reference struct {
		seid        uint64
		association *NodeAssociation
		activity    *sessionActivity
		active      bool
		err         error
		observed    time.Time
	}
	var batch [activityPollBatchSize]reference
	n := 0
	dirtyLimit := activityPollBatchSize
	if periodic && conn.activityRemaining > 0 {
		dirtyLimit /= 2
	}
	// A timer update must not wait behind a bulk association reindex or other
	// sessions' dirty entries (TS 29.244 V20.1.0 clause 5.11.2).
	if assoc := conn.activityDirty[priority]; priority != 0 && assoc != nil {
		if session := assoc.Sessions[priority]; session != nil && session.activity != nil && !session.activity.sampling && !assoc.cleaning && assoc.enhancedRelease == 0 {
			activity := session.activity
			activity.sampling = true
			activity.beginRead()
			batch[n] = reference{seid: priority, association: assoc, activity: activity}
			n++
			delete(conn.activityDirty, priority)
		}
	}
	inspected := 0
	for seid, assoc := range conn.activityDirty {
		if inspected == dirtyLimit || n == dirtyLimit {
			break
		}
		inspected++
		session := assoc.Sessions[seid]
		if session == nil || session.activity == nil || assoc.cleaning || assoc.enhancedRelease != 0 {
			delete(conn.activityDirty, seid)
			continue
		}
		activity := session.activity
		if activity.sampling {
			continue
		}
		activity.sampling = true
		activity.beginRead()
		batch[n] = reference{seid: seid, association: assoc, activity: activity}
		n++
		delete(conn.activityDirty, seid)
	}
	inspected = 0
	for periodic && n < len(batch) && inspected < len(batch) && conn.activityRemaining > 0 && conn.activityHead != nil {
		activity := conn.activityHead
		conn.unlinkSessionActivity(activity)
		conn.appendSessionActivity(activity)
		conn.activityRemaining--
		inspected++
		session := activity.association.Sessions[activity.seid]
		if activity.sampling || session == nil || session.activity != activity || activity.association.cleaning || activity.association.enhancedRelease != 0 {
			continue
		}
		activity.sampling = true
		activity.beginRead()
		batch[n] = reference{seid: activity.seid, association: activity.association, activity: activity}
		n++
	}
	more := periodic && conn.activityRemaining > 0 && inspected > 0 || len(conn.activityDirty) > 0 && n > 0
	if n == 0 {
		if conn.activityHead == nil {
			conn.activityRemaining = 0
		}
		conn.stateMu.Unlock()
		return more
	}
	conn.stateMu.Unlock()

	// Only the controller and immutable slot are touched outside stateMu. Pins
	// prevent deletion/reuse; sampling prevents an empty concurrent read from
	// overtaking a still-unapplied positive observation.
	for i := range batch[:n] {
		item := &batch[i]
		item.active, item.err = item.activity.controller.ConsumeSessionActivity(item.activity.slot)
		item.observed = time.Now()
		if item.observed.Before(now) {
			item.observed = now
		}
	}
	conn.stateMu.Lock()
	var requests []admittedRequest
	for _, item := range batch[:n] {
		seid, assoc, activity := item.seid, item.association, item.activity
		activity.sampling = false
		session := assoc.Sessions[seid]
		if conn.isClosed() || session == nil || assoc.cleaning || assoc.enhancedRelease != 0 || session.activity != activity {
			continue
		}
		if item.err != nil {
			conn.failInactivityLocked(fmt.Errorf("session %d activity: %w", seid, item.err))
			continue
		}
		if item.active && activity.last.Before(item.observed) {
			activity.last = item.observed
		}
		elapsed := item.observed.Sub(activity.last)
		if conn.inactivityReleaseTimeout > 0 && elapsed >= conn.inactivityReleaseTimeout {
			if _, err := conn.beginLocalSessionReleaseLocked(assoc, session); err != nil {
				log.Warn().Err(err).Uint64("seid", seid).Msg("Inactivity release awaits safe deletion")
			}
			continue
		}
		if !session.inactivityArmed || elapsed < session.inactivityTimer {
			continue
		}
		request := message.NewSessionReportRequest(session.RemoteSEID, 0, ie.NewReportType(1, 0, 0, 0))
		peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort(session.controlIP(conn).String(), "8805"))
		if err != nil {
			conn.failInactivityLocked(err)
			continue
		}
		socket := conn.socket()
		wire, err := conn.prepareRequestContext(request, peer, session.Traced, socket, entityAddresses(session.CPFSEIDIPv4, session.CPFSEIDIPv6, assoc.Addr), assoc, session.LocalSEID)
		if err != nil {
			// Capacity is transient. Keep the timer armed until the report is admitted.
			log.Debug().Err(err).Uint64("seid", seid).Msg("Inactivity report awaits delivery capacity")
			continue
		}
		session.inactivityArmed = false
		requests = append(requests, admittedRequest{wire, request.MessageType(), peer, socket, session.Traced})
	}
	if conn.activityHead == nil {
		conn.activityRemaining = 0
	}
	conn.stateMu.Unlock()
	for _, item := range batch[:n] {
		item.activity.endRead()
	}
	if err := conn.sendAdmitted(requests); err != nil {
		log.Warn().Err(err).Msg("Send inactivity report")
	}
	return more
}

func (conn *PfcpConnection) failInactivityLocked(err error) {
	conn.terminalError = err
	if conn.failures != nil {
		select {
		case conn.failures <- err:
		default:
		}
	}
}
