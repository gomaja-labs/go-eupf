package core

import (
	"errors"
	"net"
	"sync"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
)

// sessionMapProxy lets a validated plan bind to its journal only when applying.
type sessionMapProxy struct{ ebpf.ForwardingPlaneController }

// prepareSessionMutation creates the private reservation view under stateMu.
// Parsing and validation finish before map publication. Commit then
// reserves every rule slot before applying the first map write.
func (conn *PfcpConnection) prepareSessionMutation(session *Session, kind sessionMutationKind) (func() error, func(bool) error) {
	if session.buffers != nil {
		waitBufferIO(session.buffers.owner)
	}
	maps, resources := conn.mapOperations, conn.ResourceManager
	unlockReservations := resources.LockReservations()
	owner := session.LocalSEID
	journal := resources.BeginReservation(owner)
	reserved := journal.View()
	proxy := &sessionMapProxy{maps}
	conn.mapOperations, conn.ResourceManager = proxy, reserved
	var tx ebpf.RuleTransaction
	start := func() error {
		var err error
		tx, err = maps.BeginRuleTransaction(session.LocalSEID)
		if err == nil {
			proxy.ForwardingPlaneController = tx
		}
		if err != nil {
			return &requestIEError{ie.CauseSystemFailure, 0, err}
		}
		if session.bufferPlan != nil {
			if err := session.bufferPlan.begin(conn, tx); err != nil {
				return err
			}
		}
		keys := make([]ebpf.PDRKey, 0, len(session.PDRs))
		for id, pdr := range session.PDRs {
			keys = append(keys, ebpf.PDRKey{ID: id, TEID: pdr.Teid, IPv4: pdr.Ipv4, IPv6: pdr.Ipv6, IPv6Mask: pdr.PdrInfo.UEIPv6Mask})
		}
		if err := proxy.CheckPDRPlan(session.LocalSEID, keys); err != nil {
			var plan *ebpf.PDRPlanError
			if errors.As(err, &plan) {
				return &ruleFailure{ie.RuleIDTypePDR, plan.ID, err}
			}
			return &requestIEError{ie.CauseSystemFailure, 0, err}
		}
		return nil
	}
	finished := false
	finish := func(commit bool) error {
		if finished {
			return nil
		}
		finished = true
		defer func() { session.bufferPlan = nil }()
		defer unlockReservations()
		defer func() { conn.mapOperations, conn.ResourceManager = maps, resources }()
		retirement := func(reclaim func() error, committing bool) (func() error, func()) {
			release := kind == createSessionMutation && !committing || kind == deleteSessionMutation && committing
			if !release {
				return reclaim, func() {}
			}
			completion := &sessionRetirement{release: func() { resources.ReleaseSession(owner) }}
			var packetOwner *bufferOwner
			if session.buffers != nil && session.bufferPlan != nil && session.bufferPlan.owner != nil {
				packetOwner = session.buffers.owner
				packetOwner.retirement = completion
			}
			resourcesDone := make(chan struct{})
			var resourceCompletion sync.Once
			if packetOwner != nil {
				packetOwner.resourcesDone = resourcesDone
			}
			return func() error {
				err := reclaimReservations(reclaim)
				if err == nil {
					if packetOwner == nil {
						completion.retired()
					} else {
						resourceCompletion.Do(func() { close(resourcesDone) })
					}
				}
				return err
			}, completion.allow
		}
		if tx == nil {
			reclaim, allow := retirement(journal.Rollback(), false)
			err := reclaimReservations(reclaim)
			if err == nil {
				allow()
			}
			return err
		}
		async, deferred := tx.(interface {
			RetireResources(func() error)
			UsageCompletion() <-chan error
		})
		rollback := func() error {
			reclaim, allow := retirement(journal.Rollback(), false)
			if deferred {
				async.RetireResources(reclaim)
			}
			err := tx.Rollback()
			if !deferred && err == nil {
				err = reclaimReservations(reclaim)
			}
			// The deferred callback runs only after a successful undo and
			// reclamation, including when the grace worker repairs the undo.
			// A creation that never became live needs no later deletion.
			if deferred || err == nil {
				allow()
			}
			if session.bufferPlan != nil {
				session.bufferPlan.finish(conn, false, err == nil)
			}
			return err
		}
		if !commit {
			return rollback()
		}
		if !deferred && journal.Releases() {
			if err := tx.SynchronizeRules(); err != nil {
				return errors.Join(err, rollback())
			}
		}
		if session.bufferPlan != nil {
			if err := session.bufferPlan.publish(conn, tx); err != nil {
				return errors.Join(err, rollback())
			}
		}
		reclaim, allow := retirement(journal.Commit(), true)
		if deferred {
			async.RetireResources(reclaim)
		}
		if err := tx.Commit(); err != nil {
			return errors.Join(err, rollback())
		}
		if session.bufferPlan != nil {
			session.bufferPlan.finish(conn, true, true)
		}
		if deferred {
			allow()
			conn.responseWait = async.UsageCompletion()
			return nil
		}
		err := reclaimReservations(reclaim)
		if err == nil {
			allow()
		}
		return err
	}
	return start, finish
}

type sessionMutationKind uint8

const (
	updateSessionMutation sessionMutationKind = iota
	createSessionMutation
	deleteSessionMutation
)

// Reclamation may finish before Commit returns. A slot is released only after
// both reclamation and the successful terminal transaction result are known.
// A failed deletion keeps its slot; a successfully rolled-back creation frees it.
type sessionRetirement struct {
	mu                   sync.Mutex
	reclaimed, permitted bool
	release              func()
}

func (completion *sessionRetirement) retired() { completion.finish(false) }
func (completion *sessionRetirement) allow()   { completion.finish(true) }
func (completion *sessionRetirement) finish(permit bool) {
	completion.mu.Lock()
	if permit {
		completion.permitted = true
	} else {
		completion.reclaimed = true
	}
	var release func()
	if completion.permitted && completion.reclaimed {
		release = completion.release
		completion.release = nil
	}
	completion.mu.Unlock()
	if release != nil {
		release()
	}
}

// reconcileSessionResources runs on the reservation view after map changes,
// before commit. An uplink UE-IP constraint also retains its address lease.
func (conn *PfcpConnection) reconcileSessionResources(session *Session) {
	if conn.ResourceManager == nil {
		return
	}
	teids := make(map[uint32]uint32)
	var ips []net.IP
	var prefixes []net.IPNet
	for id, pdr := range session.PDRs {
		if pdr.Teid != 0 {
			teids[id] = pdr.Teid
		}
		if pdr.Ipv4 != nil {
			ips = append(ips, pdr.Ipv4)
		}
		if pdr.Ipv6 != nil {
			ips = append(ips, pdr.Ipv6)
			prefixes = append(prefixes, net.IPNet{IP: pdr.Ipv6, Mask: pdr.PdrInfo.UEIPv6Mask})
		}
	}
	if conn.ResourceManager.FTEIDM != nil {
		conn.ResourceManager.FTEIDM.ReleaseUnused(session.LocalSEID, teids)
	}
	if conn.ResourceManager.IPAM != nil {
		conn.ResourceManager.IPAM.ReleaseUnused(session.LocalSEID, ips)
		conn.ResourceManager.IPAM.ReleaseUnusedPrefixes(session.LocalSEID, prefixes)
	}
}

func (proxy *sessionMapProxy) DeferUsage(id uint32, report func(ebpf.UrrInfo)) error {
	if deferred, ok := proxy.ForwardingPlaneController.(interface {
		DeferUsage(uint32, func(ebpf.UrrInfo)) error
	}); ok {
		return deferred.DeferUsage(id, report)
	}
	counters, err := proxy.DeleteUrr(id)
	if err == nil {
		report(counters)
	}
	return err
}

func deferUsage(controller ebpf.ForwardingPlaneController, id uint32, report func(ebpf.UrrInfo)) error {
	if deferred, ok := controller.(interface {
		DeferUsage(uint32, func(ebpf.UrrInfo)) error
	}); ok {
		return deferred.DeferUsage(id, report)
	}
	counters, err := controller.DeleteUrr(id)
	if err == nil {
		report(counters)
	}
	return err
}

func (proxy *sessionMapProxy) asynchronousUsage() bool {
	_, ok := proxy.ForwardingPlaneController.(interface{ UsageCompletion() <-chan error })
	return ok
}

func reclaimReservations(reclaim func() error) error {
	if reclaim == nil {
		return nil
	}
	return reclaim()
}
