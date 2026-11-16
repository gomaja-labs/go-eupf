package core

import (
	"container/heap"
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
const activityMaxInterval = 5 * time.Second

// Two observations can contribute rounding delay. A 1/40 interval bounds
// that delay to 5% of the timer, with a 200 ms floor and ten-second ceiling,
// plus the worker tick and scheduling/I/O delay (TS 29.244 V20.1.0 clause 5.11.2).
func activityObservationInterval(timer time.Duration) time.Duration {
	if timer <= 0 {
		return 0
	}
	return min(activityMaxInterval, max(activityPollInterval, timer/40))
}

// One sample may perform map I/O or admit a report. Bound work under stateMu
// independently of the number of monitored sessions.
const activityPollBatchSize = 64

// stateMu owns sampling state. The controller separately serializes map closure
// and slot allocation; packet writers change only the activity map.
type sessionActivity struct {
	controller   ebpf.SessionActivityController
	slot         uint32
	last         time.Time
	due          time.Time
	index        int
	association  *NodeAssociation
	seid         uint64
	queued       bool
	sampling     bool // stateMu prevents overlapping observations of one session.
	readersMu    sync.Mutex
	readers      int
	afterReaders func()
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
			session.inactivityRevision++
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

// activityQueue is an intrusive deadline heap owned by stateMu. A session not
// due costs one root comparison per worker tick, independent of population.
type activityQueue []*sessionActivity

func (q activityQueue) Len() int           { return len(q) }
func (q activityQueue) Less(i, j int) bool { return q[i].due.Before(q[j].due) }
func (q activityQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i]; q[i].index, q[j].index = i, j }
func (q *activityQueue) Push(value any) {
	a := value.(*sessionActivity)
	a.index = len(*q)
	a.queued = true
	*q = append(*q, a)
}
func (q *activityQueue) Pop() any {
	old := *q
	n := len(old) - 1
	a := old[n]
	old[n] = nil
	*q = old[:n]
	a.queued = false
	a.index = -1
	return a
}

func (conn *PfcpConnection) watchSessionActivity(assoc *NodeAssociation, session *Session, delta int) {
	activity := session.activity
	if delta < 0 {
		delete(conn.activitySessions, session.LocalSEID)
		delete(conn.activityDirty, session.LocalSEID)
		if activity != nil && activity.queued {
			heap.Remove(&conn.activityQueue, activity.index)
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
	conn.activitySessions[session.LocalSEID] = assoc
	activity.association, activity.seid = assoc, session.LocalSEID
	if activity.due.IsZero() {
		conn.activityDirty[session.LocalSEID] = assoc
		activity.due = activity.last
	}
	if !activity.queued && !activity.sampling && conn.activityTimer(session) > 0 {
		heap.Push(&conn.activityQueue, activity)
	}
	conn.activityCount.Store(int64(len(conn.activitySessions)))
}

func (conn *PfcpConnection) activityTimer(session *Session) time.Duration {
	timer := session.inactivityTimer
	if conn.inactivityReleaseTimeout > 0 && (timer == 0 || conn.inactivityReleaseTimeout < timer) {
		timer = conn.inactivityReleaseTimeout
	}
	return timer
}

func (conn *PfcpConnection) scheduleSessionActivity(session *Session, observed time.Time) {
	activity := session.activity
	// Keep the most recent configured cadence after a one-shot UPIR so a
	// later update still observes a bounded activity age. A zero timer stops it.
	timer := conn.activityTimer(session)
	interval := activityObservationInterval(timer)
	if interval == 0 {
		return
	}
	due := observed.Add(interval)
	deadline := time.Time{}
	if session.inactivityArmed {
		deadline = activity.last.Add(session.inactivityTimer)
	}
	if conn.inactivityReleaseTimeout > 0 {
		local := activity.last.Add(conn.inactivityReleaseTimeout)
		if deadline.IsZero() || local.Before(deadline) {
			deadline = local
		}
	}
	if deadline.After(observed) && deadline.Before(due) {
		due = deadline
	}
	activity.due = due
	if activity.queued {
		heap.Fix(&conn.activityQueue, activity.index)
	} else {
		heap.Push(&conn.activityQueue, activity)
	}
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

// TS 29.244 V20.1.0 clause 5.11.2: a timer instruction rearms reporting
// without resetting packet age. Other requests use the background sweep;
// unrelated FAR changes must not add an activity read to every request.
func (conn *PfcpConnection) serviceInactivityRequest(request message.Message) {
	if conn.activityCount.Load() == 0 {
		return
	}
	switch value := request.(type) {
	case *message.SessionEstablishmentRequest:
	case *message.SessionModificationRequest:
		if value.UserPlaneInactivityTimer == nil {
			return
		}
	default:
		return
	}
	conn.serviceInactivityUpdates(time.Now(), request.SEID())
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
	type reference struct {
		seid          uint64
		association   *NodeAssociation
		activity      *sessionActivity
		active        bool
		err           error
		observed      time.Time
		timerRevision uint64
	}
	var batch [activityPollBatchSize]reference
	n := 0
	take := func(seid uint64, assoc *NodeAssociation) bool {
		session := assoc.Sessions[seid]
		if session == nil || session.activity == nil || assoc.cleaning || assoc.enhancedRelease != 0 {
			delete(conn.activityDirty, seid)
			return false
		}
		activity := session.activity
		if activity.sampling {
			return false
		}
		if activity.queued {
			heap.Remove(&conn.activityQueue, activity.index)
		}
		activity.sampling = true
		activity.beginRead()
		batch[n] = reference{seid: seid, association: assoc, activity: activity, timerRevision: session.inactivityRevision}
		n++
		delete(conn.activityDirty, seid)
		return true
	}
	dirtyLimit := activityPollBatchSize
	if periodic && len(conn.activityQueue) > 0 && !conn.activityQueue[0].due.After(now) {
		dirtyLimit /= 2
	}
	// An explicit timer update observes its own session immediately, even when
	// the previous scheduled deadline is far away (clause 5.11.2).
	if priority != 0 {
		if assoc := conn.activitySessions[priority]; assoc != nil {
			if !take(priority, assoc) {
				conn.activityDirty[priority] = assoc
			}
		}
	}
	inspected := 0
	for seid, assoc := range conn.activityDirty {
		if inspected == dirtyLimit || n == dirtyLimit {
			break
		}
		inspected++
		take(seid, assoc)
	}
	inspected = 0
	for periodic && n < len(batch) && inspected < len(batch) && len(conn.activityQueue) > 0 && !conn.activityQueue[0].due.After(now) {
		activity := heap.Pop(&conn.activityQueue).(*sessionActivity)
		inspected++
		take(activity.seid, activity.association)
	}
	more := periodic && len(conn.activityQueue) > 0 && !conn.activityQueue[0].due.After(now) || len(conn.activityDirty) > 0 && n > 0
	if n == 0 {
		conn.stateMu.Unlock()
		return more
	}
	conn.stateMu.Unlock()

	// Only the controller and immutable slot are touched outside stateMu. Pins
	// prevent deletion/reuse; sampling prevents an empty concurrent read from
	// overtaking a still-unapplied positive observation.
	for i := range batch[:n] {
		item := &batch[i]
		// TS 29.244 V20.1.0 clause 5.11.2: an empty observation may expire
		// only as of the read's beginning:
		// a packet can arrive after the empty value was copied. A positive
		// observation covers every packet up to its completed clear instead.
		item.observed = time.Now()
		item.active, item.err = item.activity.controller.ConsumeSessionActivity(item.activity.slot)
		if item.active {
			item.observed = time.Now()
		}
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
		// A timer instruction must use an observation that began after
		// provisioning. An older empty read can precede a later packet and
		// cannot establish inactivity for the new timer (clause 5.11.2).
		if session.inactivityRevision != item.timerRevision {
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
	for _, item := range batch[:n] {
		session := item.association.Sessions[item.seid]
		if !conn.isClosed() && item.err == nil && session != nil && session.activity == item.activity && !item.association.cleaning && item.association.enhancedRelease == 0 {
			conn.scheduleSessionActivity(session, item.observed)
		}
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
