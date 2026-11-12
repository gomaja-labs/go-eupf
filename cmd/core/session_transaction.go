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
// Parsing and validation finish before the data plane is quiesced. Commit then
// reserves every rule slot before applying the first map write.
func (conn *PfcpConnection) prepareSessionMutation(sessionID uint64) (func() error, func(bool) error) {
	maps, resources := conn.mapOperations, conn.ResourceManager
	unlockReservations := resources.LockReservations()
	reserved := resources.Clone()
	proxy := &sessionMapProxy{maps}
	conn.mapOperations, conn.ResourceManager = proxy, reserved
	var tx ebpf.RuleTransaction
	start := func() error {
		var err error
		tx, err = maps.BeginRuleTransaction(sessionID)
		if err == nil {
			proxy.ForwardingPlaneController = tx
		}
		if err != nil {
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
			return nil
		}
		if !commit {
			return tx.Rollback()
		}
		if err := tx.Commit(); err != nil {
			return errors.Join(err, tx.Rollback())
		}
		resources.CommitReservations(reserved)
		return nil
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
