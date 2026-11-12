package service

import (
	"maps"
	"net"
)

// Clone creates a reservation view. The connection state lock owns the
// reservation/commit interval; individual allocator methods also take pool locks.
func (manager *ResourceManager) Clone() *ResourceManager {
	if manager == nil {
		return nil
	}
	copy := &ResourceManager{}
	if manager.IPAM != nil {
		manager.IPAM.RLock()
		copy.IPAM = &IPAM{freeIPs: make([]net.IP, len(manager.IPAM.freeIPs)), busyIPs: make(map[uint64]net.IP, len(manager.IPAM.busyIPs)), reservedIPs: maps.Clone(manager.IPAM.reservedIPs), ownerIPs: make(map[uint64]map[string]net.IP), prefixLeases: maps.Clone(manager.IPAM.prefixLeases), pool: manager.IPAM.pool}
		for i, ip := range manager.IPAM.freeIPs {
			copy.IPAM.freeIPs[i] = append(net.IP(nil), ip...)
		}
		for owner, ip := range manager.IPAM.busyIPs {
			copy.IPAM.busyIPs[owner] = append(net.IP(nil), ip...)
		}
		for owner, ips := range manager.IPAM.ownerIPs {
			copy.IPAM.ownerIPs[owner] = make(map[string]net.IP)
			for key, ip := range ips {
				copy.IPAM.ownerIPs[owner][key] = append(net.IP(nil), ip...)
			}
		}
		manager.IPAM.RUnlock()
	}
	if manager.FTEIDM != nil {
		manager.FTEIDM.RLock()
		copy.FTEIDM = &FTEIDM{freeTEIDs: append([]uint32(nil), manager.FTEIDM.freeTEIDs...), busyTEIDs: make(map[uint64]map[uint32]uint32, len(manager.FTEIDM.busyTEIDs)), reservedTEIDs: maps.Clone(manager.FTEIDM.reservedTEIDs), maximum: manager.FTEIDM.maximum}
		for owner, pdrs := range manager.FTEIDM.busyTEIDs {
			copy.FTEIDM.busyTEIDs[owner] = make(map[uint32]uint32, len(pdrs))
			for id, teid := range pdrs {
				copy.FTEIDM.busyTEIDs[owner][id] = teid
			}
		}
		manager.FTEIDM.RUnlock()
	}
	return copy
}

// CommitReservations publishes a private reservation view while the connection
// state lock excludes other session mutations. Allocator addresses remain stable.
func (manager *ResourceManager) CommitReservations(reserved *ResourceManager) {
	if manager == nil || reserved == nil {
		return
	}
	if manager.IPAM != nil && reserved.IPAM != nil {
		manager.IPAM.Lock()
		manager.IPAM.freeIPs, manager.IPAM.busyIPs = reserved.IPAM.freeIPs, reserved.IPAM.busyIPs
		manager.IPAM.reservedIPs, manager.IPAM.ownerIPs = reserved.IPAM.reservedIPs, reserved.IPAM.ownerIPs
		manager.IPAM.prefixLeases = reserved.IPAM.prefixLeases
		manager.IPAM.Unlock()
	}
	if manager.FTEIDM != nil && reserved.FTEIDM != nil {
		manager.FTEIDM.Lock()
		manager.FTEIDM.freeTEIDs, manager.FTEIDM.busyTEIDs = reserved.FTEIDM.freeTEIDs, reserved.FTEIDM.busyTEIDs
		manager.FTEIDM.reservedTEIDs = reserved.FTEIDM.reservedTEIDs
		manager.FTEIDM.Unlock()
	}
}

// ReleasesComparedWith reports whether publishing reserved would make an old
// tunnel ID or address lease available for reuse. The caller holds the shared
// reservation lock; reserved is the private request view.
func (manager *ResourceManager) ReleasesComparedWith(reserved *ResourceManager, owner uint64) bool {
	if manager == nil {
		return false
	}
	if reserved == nil {
		return true
	}
	if manager.FTEIDM != nil {
		manager.FTEIDM.RLock()
		defer manager.FTEIDM.RUnlock()
		if reserved.FTEIDM == nil {
			return len(manager.FTEIDM.busyTEIDs[owner]) != 0
		}
		for id, allocatedOwner := range manager.FTEIDM.reservedTEIDs {
			if allocatedOwner == owner && reserved.FTEIDM.reservedTEIDs[id] != owner {
				return true
			}
		}
	}
	if manager.IPAM != nil {
		manager.IPAM.RLock()
		defer manager.IPAM.RUnlock()
		if reserved.IPAM == nil {
			return len(manager.IPAM.ownerIPs[owner]) != 0
		}
		for key, allocatedOwner := range manager.IPAM.reservedIPs {
			if allocatedOwner == owner && reserved.IPAM.reservedIPs[key] != owner {
				return true
			}
		}
		for key, lease := range manager.IPAM.prefixLeases {
			if lease.Owner == owner && reserved.IPAM.prefixLeases[key].Owner != owner {
				return true
			}
		}
	}
	return false
}
