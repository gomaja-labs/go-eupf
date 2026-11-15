package core

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

const activityPollInterval = 100 * time.Millisecond

// stateMu owns sampling state. The controller separately serializes map closure
// and counter-slot allocation; packet writers change only the counter map.
type sessionActivity struct {
	controller ebpf.SessionActivityController
	slot       uint32
	observed   uint64
	last       time.Time
}

// TS 29.244 V20.1.0 clauses 5.11.2 and 8.2.83: a zero or null timer
// disables reporting; an updated nonzero timer rearms it without resetting age.
func (conn *PfcpConnection) stageSessionActivity(session *Session, timer *ie.IE) error {
	if timer != nil {
		value := time.Duration(0)
		if !isNullIE(timer) {
			var err error
			value, err = timer.UserPlaneInactivityTimer()
			if err != nil {
				return &requestIEError{ie.CauseMandatoryIEIncorrect, ie.UserPlaneInactivityTimer, err}
			}
		}
		session.inactivityTimer, session.inactivityArmed = value, value > 0
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
	slot, count, err := controller.NewSessionActivity()
	if err != nil {
		return &requestIEError{ie.CauseNoResourcesAvailable, ie.UserPlaneInactivityTimer, err}
	}
	session.activity = &sessionActivity{controller: controller, slot: slot, observed: count, last: time.Now()}
	session.activityReserved = true
	return nil
}

func (conn *PfcpConnection) watchSessionActivity(assoc *NodeAssociation, session *Session, delta int) {
	if delta < 0 {
		delete(conn.activitySessions, session.LocalSEID)
		delete(conn.activityDirty, session.LocalSEID)
		return
	}
	if session.activity == nil {
		return
	}
	if conn.activitySessions == nil {
		conn.activitySessions = make(map[uint64]*NodeAssociation)
		conn.activityDirty = make(map[uint64]*NodeAssociation)
	}
	conn.activitySessions[session.LocalSEID], conn.activityDirty[session.LocalSEID] = assoc, assoc
}

// TS 29.244 V20.1.0 clauses 5.11.2 and 5.18.2 share the received-packet
// activity source. Sampling rounds activity time upwards, never expiring early.
func (conn *PfcpConnection) serviceInactivity(now time.Time) {
	conn.stateMu.Lock()
	if conn.isClosed() {
		conn.stateMu.Unlock()
		return
	}
	sessions := conn.activityDirty
	if !now.Before(conn.nextActivityPoll) {
		sessions = conn.activitySessions
		conn.nextActivityPoll = now.Add(activityPollInterval)
	}
	var requests []admittedRequest
	for seid, assoc := range sessions {
		session := assoc.Sessions[seid]
		if session == nil || assoc.cleaning || assoc.enhancedRelease != 0 || session.activity == nil {
			continue
		}
		activity := session.activity
		count, err := activity.controller.SessionActivityCount(activity.slot)
		if err != nil {
			// A failed observation must not look like inactivity and silently discard
			// a live session. Propagate the dataplane failure to the supervisor.
			conn.failInactivityLocked(fmt.Errorf("session %d activity: %w", seid, err))
			continue
		}
		if count != activity.observed {
			activity.observed, activity.last = count, now
		}
		elapsed := now.Sub(activity.last)
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
	clear(conn.activityDirty)
	conn.stateMu.Unlock()
	if err := conn.sendAdmitted(requests); err != nil {
		log.Warn().Err(err).Msg("Send inactivity report")
	}
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
