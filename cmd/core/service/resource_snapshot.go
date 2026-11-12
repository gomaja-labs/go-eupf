package service

import (
	"maps"
	"net"
)

// ReservationJournal records only one session's reservations. Newly allocated
// identifiers are reserved immediately; removed identifiers stay reserved until
// Reclaim runs after the data-plane grace period. The caller holds the shared
// reservation lock through Commit or Rollback, never across reclamation.
type ReservationJournal struct {
	manager     *ResourceManager
	owner       uint64
	view        *ResourceManager
	oldTEIDs    map[uint32]uint32
	oldIPs      map[string]net.IP
	oldBusyIP   net.IP
	oldPrefixes map[string]ipPrefixLease
}

// BeginReservation creates a private session view without copying either pool.
func (manager *ResourceManager) BeginReservation(owner uint64) *ReservationJournal {
	journal := &ReservationJournal{manager: manager, owner: owner, view: &ResourceManager{}}
	if manager == nil {
		return journal
	}
	if pool := manager.FTEIDM; pool != nil {
		pool.RLock()
		journal.oldTEIDs = maps.Clone(pool.busyTEIDs[owner])
		journal.view.FTEIDM = &FTEIDM{parent: pool, busyTEIDs: map[uint64]map[uint32]uint32{owner: maps.Clone(journal.oldTEIDs)}, reservedTEIDs: make(map[uint32]uint64)}
		pool.RUnlock()
	}
	if pool := manager.IPAM; pool != nil {
		pool.RLock()
		journal.oldIPs = maps.Clone(pool.ownerIPs[owner])
		journal.oldBusyIP = pool.busyIPs[owner]
		journal.oldPrefixes = make(map[string]ipPrefixLease)
		journal.oldPrefixes = maps.Clone(pool.activePrefixes[owner])
		journal.view.IPAM = &IPAM{parent: pool, busyIPs: map[uint64]net.IP{owner: journal.oldBusyIP}, ownerIPs: map[uint64]map[string]net.IP{owner: maps.Clone(journal.oldIPs)}, reservedIPs: make(map[string]uint64), prefixLeases: maps.Clone(journal.oldPrefixes)}
		pool.RUnlock()
	}
	return journal
}

// View exposes allocator operations scoped to the pending session mutation.
func (journal *ReservationJournal) View() *ResourceManager { return journal.view }

// Commit publishes the session's active references, returning deferred release
// work. Reclaim is idempotent; lease generations prevent a late callback from
// freeing an identifier that has since been allocated again.
func (journal *ReservationJournal) Commit() func() error {
	return journal.publish(false)
}

// Rollback restores active references and returns the new reservations for
// deferred reclamation if the failed transaction published any rule pointers.
func (journal *ReservationJournal) Rollback() func() error { return journal.publish(true) }
func (journal *ReservationJournal) publish(rollback bool) func() error {
	owner := journal.owner
	var reclaim []func()
	if journal.manager == nil {
		return func() error { return nil }
	}
	if pool := journal.manager.FTEIDM; pool != nil {
		active := journal.view.FTEIDM.busyTEIDs[owner]
		if rollback {
			active = journal.oldTEIDs
		}
		keep := make(map[uint32]bool, len(active))
		for _, id := range active {
			keep[id] = true
		}
		pool.Lock()
		pool.busyTEIDs[owner] = maps.Clone(active)
		if len(active) == 0 {
			delete(pool.busyTEIDs, owner)
		}
		for id := range pool.ownerTEIDs[owner] {
			if keep[id] {
				continue
			}
			epoch := pool.leaseEpoch[id]
			reclaim = append(reclaim, func() {
				pool.Lock()
				defer pool.Unlock()
				if pool.reservedTEIDs[id] == owner && pool.leaseEpoch[id] == epoch {
					pool.releaseLocked(id)
					if rollback {
						pool.freeTEIDs.moveToFront(int(id) - 1)
					}
				}
			})
		}
		pool.Unlock()
	}
	if pool := journal.manager.IPAM; pool != nil {
		active, busy, prefixes := journal.view.IPAM.ownerIPs[owner], journal.view.IPAM.busyIPs[owner], journal.view.IPAM.prefixLeases
		if rollback {
			active, busy, prefixes = journal.oldIPs, journal.oldBusyIP, journal.oldPrefixes
		}
		pool.Lock()
		pool.ownerIPs[owner] = maps.Clone(active)
		if len(active) == 0 {
			delete(pool.ownerIPs, owner)
		}
		if len(busy) == 0 {
			delete(pool.busyIPs, owner)
		} else {
			pool.busyIPs[owner] = busy
		}
		for key, ip := range pool.heldIPs[owner] {
			if _, ok := active[key]; ok {
				continue
			}
			epoch := pool.leaseEpoch[key]
			reclaim = append(reclaim, func() {
				pool.Lock()
				defer pool.Unlock()
				if pool.reservedIPs[key] == owner && pool.leaseEpoch[key] == epoch {
					pool.releaseLocked(owner, key, ip)
					if rollback {
						pool.freeIPs.moveToFront(pool.indexForIP(ip))
					}
				}
			})
		}
		pool.activePrefixes[owner] = maps.Clone(prefixes)
		if len(prefixes) == 0 {
			delete(pool.activePrefixes, owner)
		}
		// Prefix references are private to the session. A retirement keeps its
		// collision claim until the grace period, like the exact UE address.
		for key := range pool.ownerPrefixes[owner] {
			if _, ok := prefixes[key]; ok {
				continue
			}
			epoch := pool.prefixEpoch[key]
			reclaim = append(reclaim, func() {
				pool.Lock()
				defer pool.Unlock()
				if lease, ok := pool.prefixLeases[key]; ok && lease.Owner == owner && pool.prefixEpoch[key] == epoch {
					ones, _ := lease.Prefix.Mask.Size()
					pool.claims.set(lease.Prefix.IP, ones, "prefix:"+key, owner, false)
					delete(pool.prefixLeases, key)
					delete(pool.ownerPrefixes[owner], key)
					if len(pool.ownerPrefixes[owner]) == 0 {
						delete(pool.ownerPrefixes, owner)
					}
					delete(pool.prefixEpoch, key)
				}
			})
		}
		pool.Unlock()
	}
	if len(reclaim) == 0 {
		return nil
	}
	return func() error {
		for _, release := range reclaim {
			release()
		}
		return nil
	}
}

// Releases reports whether the request detaches an existing tunnel or address.
func (journal *ReservationJournal) Releases() bool {
	if pool := journal.view.FTEIDM; pool != nil {
		keep := make(map[uint32]bool)
		for _, id := range pool.busyTEIDs[journal.owner] {
			keep[id] = true
		}
		for _, id := range journal.oldTEIDs {
			if !keep[id] {
				return true
			}
		}
	}
	if pool := journal.view.IPAM; pool != nil {
		for key := range journal.oldIPs {
			if _, ok := pool.ownerIPs[journal.owner][key]; !ok {
				return true
			}
		}
		for key := range journal.oldPrefixes {
			if _, ok := pool.prefixLeases[key]; !ok {
				return true
			}
		}
	}
	return false
}
