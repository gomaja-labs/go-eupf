package core

import (
	"errors"
	"net"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
)

// sessionMapProxy lets a validated plan bind to its journal only when applying.
type sessionMapProxy struct{ ebpf.ForwardingPlaneController }

// prepareSessionMutation creates the private reservation view under stateMu.
// Parsing and validation finish before map publication. Commit then
// reserves every rule slot before applying the first map write.
func (conn *PfcpConnection) prepareSessionMutation(session *Session) (func() error, func(bool) error) {
	maps, resources := conn.mapOperations, conn.ResourceManager
	unlockReservations := resources.LockReservations()
	journal := resources.BeginReservation(session.LocalSEID)
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
		defer unlockReservations()
		defer func() { conn.mapOperations, conn.ResourceManager = maps, resources }()
		if tx == nil {
			return reclaimReservations(journal.Rollback())
		}
		async, deferred := tx.(interface {
			RetireResources(func() error)
			UsageCompletion() <-chan error
		})
		if !commit {
			reclaim := journal.Rollback()
			if deferred {
				async.RetireResources(reclaim)
			}
			err := tx.Rollback()
			if !deferred && err == nil {
				err = reclaimReservations(reclaim)
			}
			return err
		}
		if !deferred && journal.Releases() {
			if err := tx.SynchronizeRules(); err != nil {
				reclaim := journal.Rollback()
				rollback := tx.Rollback()
				if rollback == nil {
					_ = reclaimReservations(reclaim)
				}
				return errors.Join(err, rollback)
			}
		}
		reclaim := journal.Commit()
		if deferred {
			async.RetireResources(reclaim)
		}
		if err := tx.Commit(); err != nil {
			reclaim = journal.Rollback()
			if deferred {
				async.RetireResources(reclaim)
			}
			rollback := tx.Rollback()
			if !deferred && rollback == nil {
				_ = reclaimReservations(reclaim)
			}
			return errors.Join(err, rollback)
		}
		if deferred {
			conn.responseWait = async.UsageCompletion()
			return nil
		}
		return reclaimReservations(reclaim)
	}
	return start, finish
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
