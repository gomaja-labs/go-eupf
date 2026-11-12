// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package service

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/korylprince/ipnetgen"
)

// MaxResourcePoolSize bounds each eagerly materialized pool to one million
// entries. IPv4 pools omit the network address. IPv6 prefix allocation is not
// implemented by this allocator.
const MaxResourcePoolSize = 1 << 20

var ErrResourceCollision = errors.New("resource belongs to another session")
var ErrResourceExhausted = errors.New("resource pool exhausted")

type ResourceManager struct {
	nextSEID      atomic.Uint64
	transactionMu sync.Mutex
	IPAM          *IPAM
	FTEIDM        *FTEIDM
}
type FTEIDM struct {
	sync.RWMutex
	freeTEIDs     []uint32
	busyTEIDs     map[uint64]map[uint32]uint32
	reservedTEIDs map[uint32]uint64
	maximum       uint32
}
type ipPrefixLease struct {
	Owner  uint64
	Prefix net.IPNet
}

type IPAM struct {
	sync.RWMutex
	freeIPs      []net.IP
	busyIPs      map[uint64]net.IP
	reservedIPs  map[string]uint64
	ownerIPs     map[uint64]map[string]net.IP
	pool         *net.IPNet
	prefixLeases map[string]ipPrefixLease
}

func NewResourceManager(ipRange string, teidRange uint32) (*ResourceManager, error) {
	if teidRange > MaxResourcePoolSize {
		return nil, fmt.Errorf("fteid_pool %d exceeds limit %d", teidRange, MaxResourcePoolSize)
	}
	var prefix *net.IPNet
	if ipRange != "" {
		var err error
		_, prefix, err = net.ParseCIDR(ipRange)
		if err != nil {
			return nil, fmt.Errorf("ueip_pool: %w", err)
		}
		ones, bits := prefix.Mask.Size()
		if bits != 32 {
			return nil, fmt.Errorf("ueip_pool supports IPv4 only")
		}
		if uint64(1)<<uint(32-ones)-1 > MaxResourcePoolSize {
			return nil, fmt.Errorf("ueip_pool %s exceeds limit %d", ipRange, MaxResourcePoolSize)
		}
	}
	manager := &ResourceManager{
		IPAM:   &IPAM{busyIPs: make(map[uint64]net.IP), reservedIPs: make(map[string]uint64), ownerIPs: make(map[uint64]map[string]net.IP), prefixLeases: make(map[string]ipPrefixLease), pool: prefix},
		FTEIDM: &FTEIDM{busyTEIDs: make(map[uint64]map[uint32]uint32), reservedTEIDs: make(map[uint32]uint64), maximum: teidRange},
	}
	if ipRange != "" {
		generator, err := ipnetgen.New(ipRange)
		if err != nil {
			return nil, err
		}
		generator.Next()
		for ip := generator.Next(); ip != nil; ip = generator.Next() {
			manager.IPAM.freeIPs = append(manager.IPAM.freeIPs, ip)
		}
	}
	for teid := uint32(1); teid <= teidRange; teid++ {
		manager.FTEIDM.freeTEIDs = append(manager.FTEIDM.freeTEIDs, teid)
	}
	return manager, nil
}
func (pool *IPAM) AllocateIP(owner uint64) (net.IP, error) {
	pool.Lock()
	defer pool.Unlock()
	if ip, ok := pool.busyIPs[owner]; ok {
		return append(net.IP(nil), ip...), nil
	}
	if len(pool.freeIPs) == 0 {
		return nil, ErrResourceExhausted
	}
	ip := pool.freeIPs[0]
	pool.freeIPs = pool.freeIPs[1:]
	pool.record(owner, ip)
	pool.busyIPs[owner] = ip
	return append(net.IP(nil), ip...), nil
}
func (pool *IPAM) record(owner uint64, ip net.IP) {
	key := ip.String()
	pool.reservedIPs[key] = owner
	if pool.ownerIPs[owner] == nil {
		pool.ownerIPs[owner] = make(map[string]net.IP)
	}
	pool.ownerIPs[owner][key] = append(net.IP(nil), ip...)
}

// ReserveIP keeps explicit addresses out of the allocation pool as well.
// TS 29.244 V20.1.0 clauses 5.2.1 and 5.21.
func (pool *IPAM) ReserveIP(owner uint64, ip net.IP) error {
	if ip.To16() == nil {
		return fmt.Errorf("invalid UE IP address")
	}
	pool.Lock()
	defer pool.Unlock()
	key := ip.String()
	for _, lease := range pool.prefixLeases {
		if lease.Owner != owner && lease.Prefix.Contains(ip) {
			return ErrResourceCollision
		}
	}
	if current, ok := pool.reservedIPs[key]; ok {
		if current != owner {
			return ErrResourceCollision
		}
		return nil
	}
	for i, free := range pool.freeIPs {
		if free.Equal(ip) {
			pool.freeIPs = append(pool.freeIPs[:i], pool.freeIPs[i+1:]...)
			break
		}
	}
	pool.record(owner, ip)
	return nil
}
func (pool *IPAM) ReleaseIP(owner uint64) {
	pool.Lock()
	defer pool.Unlock()
	for key, ip := range pool.ownerIPs[owner] {
		if pool.pool != nil && pool.pool.Contains(ip) && !pool.pool.IP.Equal(ip) {
			pool.freeIPs = append(pool.freeIPs, ip)
		}
		delete(pool.reservedIPs, key)
	}
	for key, lease := range pool.prefixLeases {
		if lease.Owner == owner {
			delete(pool.prefixLeases, key)
		}
	}
	delete(pool.ownerIPs, owner)
	delete(pool.busyIPs, owner)
}

// ReleaseUnused retains the chosen address only while a PDR still references it.
func (pool *IPAM) ReleaseUnused(owner uint64, active []net.IP) {
	pool.Lock()
	defer pool.Unlock()
	keep := make(map[string]bool, len(active))
	for _, ip := range active {
		keep[ip.String()] = true
	}
	for key, ip := range pool.ownerIPs[owner] {
		if keep[key] {
			continue
		}
		if pool.pool != nil && pool.pool.Contains(ip) && !pool.pool.IP.Equal(ip) {
			pool.freeIPs = append(pool.freeIPs, ip)
		}
		delete(pool.reservedIPs, key)
		delete(pool.ownerIPs[owner], key)
		if pool.busyIPs[owner].Equal(ip) {
			delete(pool.busyIPs, owner)
		}
	}
}
func (pool *FTEIDM) AllocateTEID(owner uint64, pdr uint32) (uint32, error) {
	pool.Lock()
	defer pool.Unlock()
	if teid, ok := pool.busyTEIDs[owner][pdr]; ok {
		return teid, nil
	}
	if len(pool.freeTEIDs) == 0 {
		return 0, ErrResourceExhausted
	}
	teid := pool.freeTEIDs[0]
	pool.freeTEIDs = pool.freeTEIDs[1:]
	pool.record(owner, pdr, teid)
	return teid, nil
}
func (pool *FTEIDM) record(owner uint64, pdr, teid uint32) {
	if pool.busyTEIDs[owner] == nil {
		pool.busyTEIDs[owner] = make(map[uint32]uint32)
	}
	pool.busyTEIDs[owner][pdr] = teid
	pool.reservedTEIDs[teid] = owner
}

// ReserveTEID also permits same-session CHOOSE-ID sharing, while keeping every
// explicit TEID out of subsequent allocations. TS 29.244 clause 5.5.3.
func (pool *FTEIDM) ReserveTEID(owner uint64, pdr, teid uint32) error {
	if teid == 0 {
		return fmt.Errorf("TEID zero cannot identify a user-plane tunnel")
	}
	pool.Lock()
	defer pool.Unlock()
	if current, ok := pool.reservedTEIDs[teid]; ok && current != owner {
		return ErrResourceCollision
	}
	for i, free := range pool.freeTEIDs {
		if free == teid {
			pool.freeTEIDs = append(pool.freeTEIDs[:i], pool.freeTEIDs[i+1:]...)
			break
		}
	}
	pool.record(owner, pdr, teid)
	return nil
}
func (pool *FTEIDM) ReleaseTEID(owner uint64) {
	pool.Lock()
	defer pool.Unlock()
	for teid, current := range pool.reservedTEIDs {
		if current == owner {
			if teid <= pool.maximum {
				pool.freeTEIDs = append(pool.freeTEIDs, teid)
			}
			delete(pool.reservedTEIDs, teid)
		}
	}
	delete(pool.busyTEIDs, owner)
}

// ReleaseUnused frees a shared F-TEID only after its final PDR reference.
// TS 29.244 V20.1.0 clause 5.5.3.
func (pool *FTEIDM) ReleaseUnused(owner uint64, active map[uint32]uint32) {
	pool.Lock()
	defer pool.Unlock()
	keep := make(map[uint32]bool, len(active))
	for _, teid := range active {
		keep[teid] = true
	}
	for teid, current := range pool.reservedTEIDs {
		if current == owner && !keep[teid] {
			if teid <= pool.maximum {
				pool.freeTEIDs = append(pool.freeTEIDs, teid)
			}
			delete(pool.reservedTEIDs, teid)
		}
	}
	delete(pool.busyTEIDs, owner)
	for pdr, teid := range active {
		if current, ok := pool.reservedTEIDs[teid]; ok && current == owner {
			if pool.busyTEIDs[owner] == nil {
				pool.busyTEIDs[owner] = make(map[uint32]uint32)
			}
			pool.busyTEIDs[owner][pdr] = teid
		}
	}
}

// ReserveIPv6Prefix claims the UE prefix, even for uplink-only PDRs. Exact
// address reservations alone cannot prevent another session taking its subnet.
// TS 29.244 V20.1.0 clauses 5.21 and 8.2.62.
func (pool *IPAM) ReserveIPv6Prefix(owner uint64, ip net.IP, mask net.IPMask) error {
	ones, bits := mask.Size()
	if ip.To4() != nil || ip.To16() == nil || bits != 128 {
		return fmt.Errorf("invalid IPv6 prefix")
	}
	prefix := net.IPNet{IP: append(net.IP(nil), ip.To16().Mask(mask)...), Mask: append(net.IPMask(nil), mask...)}
	pool.Lock()
	defer pool.Unlock()
	for _, lease := range pool.prefixLeases {
		if lease.Owner != owner && (prefix.Contains(lease.Prefix.IP) || lease.Prefix.Contains(prefix.IP)) {
			return ErrResourceCollision
		}
	}
	for address, current := range pool.reservedIPs {
		if current != owner && prefix.Contains(net.ParseIP(address)) {
			return ErrResourceCollision
		}
	}
	if pool.prefixLeases == nil {
		pool.prefixLeases = make(map[string]ipPrefixLease)
	}
	key := fmt.Sprintf("%s/%d", ip.String(), ones)
	pool.prefixLeases[key] = ipPrefixLease{owner, prefix}
	pool.record(owner, ip)
	return nil
}

// ReleaseUnusedPrefixes removes superseded prefix lengths as well as addresses.
func (pool *IPAM) ReleaseUnusedPrefixes(owner uint64, active []net.IPNet) {
	keep := make(map[string]bool, len(active))
	for _, prefix := range active {
		ones, _ := prefix.Mask.Size()
		keep[fmt.Sprintf("%s/%d", prefix.IP.String(), ones)] = true
	}
	pool.Lock()
	defer pool.Unlock()
	for key, lease := range pool.prefixLeases {
		if lease.Owner == owner && !keep[key] {
			delete(pool.prefixLeases, key)
		}
	}
}

// NextSessionID allocates a process-lifetime identity across every PFCP endpoint
// sharing this forwarding plane. Zero signals exhaustion; live IDs never wrap.
// TS 29.244 V20.1.0 clauses 5.2.1 and 5.6.2.
func (manager *ResourceManager) NextSessionID() uint64 {
	for {
		previous := manager.nextSEID.Load()
		if previous == ^uint64(0) {
			return 0
		}
		next := previous + 1
		if next == 1 {
			next = 2
		}
		if manager.nextSEID.CompareAndSwap(previous, next) {
			return next
		}
	}
}

// LockReservations serializes private reservation snapshots across N4/Sxa/Sxb.
// Lock order is connection state, shared reservations, then the map journal.
func (manager *ResourceManager) LockReservations() func() {
	if manager == nil {
		return func() {}
	}
	manager.transactionMu.Lock()
	return manager.transactionMu.Unlock
}
