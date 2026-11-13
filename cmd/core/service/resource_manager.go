// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package service

import (
	"encoding/binary"
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
	replay        ReplayBudget
	nextSEID      atomic.Uint64
	shuttingDown  atomic.Bool
	transactionMu sync.Mutex
	IPAM          *IPAM
	FTEIDM        *FTEIDM
}
type FTEIDM struct {
	parent     *FTEIDM
	ownerTEIDs map[uint64]map[uint32]bool
	leaseEpoch map[uint32]uint64
	nextEpoch  uint64
	sync.RWMutex
	freeTEIDs     freeChain
	busyTEIDs     map[uint64]map[uint32]uint32
	reservedTEIDs map[uint32]uint64
	maximum       uint32
}
type ipPrefixLease struct {
	Owner  uint64
	Prefix net.IPNet
}

type IPAM struct {
	baseIPv4       uint32
	claims         *reservationTrie
	activePrefixes map[uint64]map[string]ipPrefixLease
	parent         *IPAM
	heldIPs        map[uint64]map[string]net.IP
	ownerPrefixes  map[uint64]map[string]bool
	leaseEpoch     map[string]uint64
	prefixEpoch    map[string]uint64
	nextEpoch      uint64
	sync.RWMutex
	freeIPs      freeChain
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
		IPAM:   &IPAM{claims: &reservationTrie{}, activePrefixes: make(map[uint64]map[string]ipPrefixLease), heldIPs: make(map[uint64]map[string]net.IP), ownerPrefixes: make(map[uint64]map[string]bool), leaseEpoch: make(map[string]uint64), prefixEpoch: make(map[string]uint64), busyIPs: make(map[uint64]net.IP), reservedIPs: make(map[string]uint64), ownerIPs: make(map[uint64]map[string]net.IP), prefixLeases: make(map[string]ipPrefixLease), pool: prefix},
		FTEIDM: &FTEIDM{ownerTEIDs: make(map[uint64]map[uint32]bool), leaseEpoch: make(map[uint32]uint64), busyTEIDs: make(map[uint64]map[uint32]uint32), reservedTEIDs: make(map[uint32]uint64), maximum: teidRange},
	}
	if ipRange != "" {
		generator, err := ipnetgen.New(ipRange)
		if err != nil {
			return nil, err
		}
		ones, _ := prefix.Mask.Size()
		size := int((uint64(1) << uint(32-ones)) - 1)
		manager.IPAM.freeIPs = newFreeChain(size)
		if size > 0 {
			generator.Next()
			first := generator.Next()
			manager.IPAM.baseIPv4 = binary.BigEndian.Uint32(first.To4()) - 1
		}
	} else {
		manager.IPAM.freeIPs = newFreeChain(0)
	}
	manager.FTEIDM.freeTEIDs = newFreeChain(int(teidRange))
	return manager, nil
}
func (pool *IPAM) AllocateIP(owner uint64) (net.IP, error) {
	if pool.parent != nil {
		if ip := pool.busyIPs[owner]; len(ip) > 0 {
			return append(net.IP(nil), ip...), nil
		}
		ip, err := pool.parent.AllocateIP(owner)
		if err == nil {
			pool.record(owner, ip)
			pool.busyIPs[owner] = ip
		}
		return append(net.IP(nil), ip...), err
	}
	pool.Lock()
	defer pool.Unlock()
	if ip, ok := pool.busyIPs[owner]; ok {
		return append(net.IP(nil), ip...), nil
	}
	if pool.freeIPs.len() == 0 {
		return nil, ErrResourceExhausted
	}
	index := pool.freeIPs.first()
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, pool.baseIPv4+uint32(index)+1)
	pool.freeIPs.remove(index)
	pool.record(owner, ip)
	pool.busyIPs[owner] = ip
	return append(net.IP(nil), ip...), nil
}
func (pool *IPAM) record(owner uint64, ip net.IP) {
	key := ip.String()
	if pool.parent == nil {
		if _, exists := pool.reservedIPs[key]; !exists {
			pool.nextEpoch++
			pool.leaseEpoch[key] = pool.nextEpoch
		}
		if pool.heldIPs[owner] == nil {
			pool.heldIPs[owner] = make(map[string]net.IP)
		}
		pool.heldIPs[owner][key] = append(net.IP(nil), ip...)
		if ip.To4() == nil {
			pool.claims.set(ip, 128, "ip:"+key, owner, true)
		}
	}
	pool.reservedIPs[key] = owner
	if pool.ownerIPs[owner] == nil {
		pool.ownerIPs[owner] = make(map[string]net.IP)
	}
	pool.ownerIPs[owner][key] = append(net.IP(nil), ip...)
}

// ReserveIP keeps explicit addresses out of the allocation pool as well.
// TS 29.244 V20.1.0 clauses 5.2.1 and 5.21.
func (pool *IPAM) ReserveIP(owner uint64, ip net.IP) error {
	if pool.parent != nil {
		if err := pool.parent.ReserveIP(owner, ip); err != nil {
			return err
		}
		pool.record(owner, ip)
		return nil
	}
	if ip.To16() == nil {
		return fmt.Errorf("invalid UE IP address")
	}
	pool.Lock()
	defer pool.Unlock()
	key := ip.String()
	if ip.To4() == nil && pool.claims.conflicts(ip, 128, owner) {
		return ErrResourceCollision
	}
	if current, ok := pool.reservedIPs[key]; ok {
		if current != owner {
			return ErrResourceCollision
		}
		if _, active := pool.ownerIPs[owner][key]; !active {
			return ErrResourceCollision
		}
		return nil
	}
	pool.takeFreeLocked(ip)
	pool.record(owner, ip)
	return nil
}
func (pool *IPAM) ReleaseIP(owner uint64) {
	if pool.parent != nil {
		delete(pool.ownerIPs, owner)
		delete(pool.busyIPs, owner)
		for key, lease := range pool.prefixLeases {
			if lease.Owner == owner {
				delete(pool.prefixLeases, key)
			}
		}
		return
	}
	pool.Lock()
	defer pool.Unlock()
	for key, ip := range pool.heldIPs[owner] {
		pool.releaseLocked(owner, key, ip)
	}
	for key := range pool.ownerPrefixes[owner] {
		lease := pool.prefixLeases[key]
		ones, _ := lease.Prefix.Mask.Size()
		pool.claims.set(lease.Prefix.IP, ones, "prefix:"+key, owner, false)
		delete(pool.prefixLeases, key)
		delete(pool.prefixEpoch, key)
	}
	delete(pool.ownerPrefixes, owner)
	delete(pool.activePrefixes, owner)
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
		if pool.parent == nil {
			pool.releaseLocked(owner, key, ip)
		} else {
			delete(pool.ownerIPs[owner], key)
		}
		if pool.busyIPs[owner].Equal(ip) {
			delete(pool.busyIPs, owner)
		}
	}
}
func (pool *FTEIDM) AllocateTEID(owner uint64, pdr uint32) (uint32, error) {
	if pool.parent != nil {
		if id := pool.busyTEIDs[owner][pdr]; id != 0 {
			return id, nil
		}
		id, err := pool.parent.AllocateTEID(owner, pdr)
		if err == nil {
			pool.record(owner, pdr, id)
		}
		return id, err
	}
	pool.Lock()
	defer pool.Unlock()
	if teid, ok := pool.busyTEIDs[owner][pdr]; ok {
		return teid, nil
	}
	if pool.freeTEIDs.len() == 0 {
		return 0, ErrResourceExhausted
	}
	teid := uint32(pool.freeTEIDs.first()) + 1
	pool.takeFreeLocked(teid)
	pool.record(owner, pdr, teid)
	return teid, nil
}
func (pool *FTEIDM) record(owner uint64, pdr, teid uint32) {
	if pool.busyTEIDs[owner] == nil {
		pool.busyTEIDs[owner] = make(map[uint32]uint32)
	}
	pool.busyTEIDs[owner][pdr] = teid
	if pool.parent == nil {
		if _, exists := pool.reservedTEIDs[teid]; !exists {
			pool.nextEpoch++
			pool.leaseEpoch[teid] = pool.nextEpoch
		}
		if pool.ownerTEIDs[owner] == nil {
			pool.ownerTEIDs[owner] = make(map[uint32]bool)
		}
		pool.ownerTEIDs[owner][teid] = true
	}
	pool.reservedTEIDs[teid] = owner
}

// ReserveTEID also permits same-session CHOOSE-ID sharing, while keeping every
// explicit TEID out of subsequent allocations. TS 29.244 clause 5.5.3.
func (pool *FTEIDM) ReserveTEID(owner uint64, pdr, teid uint32) error {
	if pool.parent != nil {
		if err := pool.parent.ReserveTEID(owner, pdr, teid); err != nil {
			return err
		}
		pool.record(owner, pdr, teid)
		return nil
	}
	if teid == 0 {
		return fmt.Errorf("TEID zero cannot identify a user-plane tunnel")
	}
	pool.Lock()
	defer pool.Unlock()
	if current, ok := pool.reservedTEIDs[teid]; ok {
		if current != owner {
			return ErrResourceCollision
		}
		active := false
		for _, id := range pool.busyTEIDs[owner] {
			if id == teid {
				active = true
				break
			}
		}
		if !active {
			return ErrResourceCollision
		}
	}
	pool.takeFreeLocked(teid)
	pool.record(owner, pdr, teid)
	return nil
}
func (pool *FTEIDM) ReleaseTEID(owner uint64) {
	if pool.parent != nil {
		delete(pool.busyTEIDs, owner)
		return
	}
	pool.Lock()
	defer pool.Unlock()
	for id := range pool.ownerTEIDs[owner] {
		pool.releaseLocked(id)
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
	if pool.parent == nil {
		for id := range pool.ownerTEIDs[owner] {
			if !keep[id] {
				pool.releaseLocked(id)
			}
		}
	}
	delete(pool.busyTEIDs, owner)
	for pdr, teid := range active {
		if current, ok := pool.reservedTEIDs[teid]; (ok && current == owner) || pool.parent != nil {
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
	if pool.parent != nil {
		if err := pool.parent.ReserveIPv6Prefix(owner, ip, mask); err != nil {
			return err
		}
		ones, _ := mask.Size()
		key := fmt.Sprintf("%s/%d", ip.String(), ones)
		if pool.prefixLeases == nil {
			pool.prefixLeases = make(map[string]ipPrefixLease)
		}
		pool.prefixLeases[key] = ipPrefixLease{owner, net.IPNet{IP: ip.Mask(mask), Mask: append(net.IPMask(nil), mask...)}}
		pool.record(owner, ip)
		return nil
	}
	ones, bits := mask.Size()
	if ip.To4() != nil || ip.To16() == nil || bits != 128 {
		return fmt.Errorf("invalid IPv6 prefix")
	}
	prefix := net.IPNet{IP: append(net.IP(nil), ip.To16().Mask(mask)...), Mask: append(net.IPMask(nil), mask...)}
	pool.Lock()
	defer pool.Unlock()
	if pool.claims.conflicts(prefix.IP, ones, owner) {
		return ErrResourceCollision
	}
	key := fmt.Sprintf("%s/%d", ip.String(), ones)
	if existing, ok := pool.prefixLeases[key]; ok && existing.Owner == owner {
		if _, active := pool.activePrefixes[owner][key]; !active {
			return ErrResourceCollision
		}
	}
	if current, ok := pool.reservedIPs[ip.String()]; ok && current == owner {
		if _, active := pool.ownerIPs[owner][ip.String()]; !active {
			return ErrResourceCollision
		}
	}
	if pool.prefixLeases == nil {
		pool.prefixLeases = make(map[string]ipPrefixLease)
	}
	pool.prefixLeases[key] = ipPrefixLease{owner, prefix}
	pool.claims.set(prefix.IP, ones, "prefix:"+key, owner, true)
	if pool.activePrefixes[owner] == nil {
		pool.activePrefixes[owner] = make(map[string]ipPrefixLease)
	}
	pool.activePrefixes[owner][key] = ipPrefixLease{owner, prefix}
	if pool.ownerPrefixes[owner] == nil {
		pool.ownerPrefixes[owner] = make(map[string]bool)
	}
	pool.ownerPrefixes[owner][key] = true
	pool.nextEpoch++
	pool.prefixEpoch[key] = pool.nextEpoch
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
	if pool.parent != nil {
		for key, lease := range pool.prefixLeases {
			if lease.Owner == owner && !keep[key] {
				delete(pool.prefixLeases, key)
			}
		}
		return
	}
	for key := range pool.ownerPrefixes[owner] {
		if !keep[key] {
			lease := pool.prefixLeases[key]
			ones, _ := lease.Prefix.Mask.Size()
			pool.claims.set(lease.Prefix.IP, ones, "prefix:"+key, owner, false)
			delete(pool.prefixLeases, key)
			delete(pool.ownerPrefixes[owner], key)
			delete(pool.prefixEpoch, key)
			delete(pool.activePrefixes[owner], key)
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

// LockReservations serializes reservation journals across N4/Sxa/Sxb.
// Lock order is connection state, shared reservations, then the map journal.
func (manager *ResourceManager) LockReservations() func() {
	if manager == nil {
		return func() {}
	}
	manager.transactionMu.Lock()
	return manager.transactionMu.Unlock
}

// BeginShutdown latches shutdown across all PFCP endpoints sharing the UPF.
func (manager *ResourceManager) BeginShutdown() { manager.shuttingDown.Store(true) }

// ShuttingDown reports whether the process has stopped accepting associations.
func (manager *ResourceManager) ShuttingDown() bool {
	return manager != nil && manager.shuttingDown.Load()
}

func (pool *IPAM) indexForIP(ip net.IP) int {
	address := ip.To4()
	if address == nil {
		return -1
	}
	value := binary.BigEndian.Uint32(address)
	if value <= pool.baseIPv4 {
		return -1
	}
	index := int(uint64(value) - uint64(pool.baseIPv4) - 1)
	if index >= len(pool.freeIPs.available) {
		return -1
	}
	return index
}
func (pool *IPAM) takeFreeLocked(ip net.IP) { pool.freeIPs.remove(pool.indexForIP(ip)) }
func (pool *IPAM) releaseLocked(owner uint64, key string, ip net.IP) {
	if pool.pool != nil && pool.pool.Contains(ip) && !pool.pool.IP.Equal(ip) {
		pool.freeIPs.addBack(pool.indexForIP(ip))
	}
	if ip.To4() == nil {
		pool.claims.set(ip, 128, "ip:"+key, owner, false)
	}
	delete(pool.reservedIPs, key)
	delete(pool.ownerIPs[owner], key)
	delete(pool.heldIPs[owner], key)
	if len(pool.heldIPs[owner]) == 0 {
		delete(pool.heldIPs, owner)
	}
	delete(pool.leaseEpoch, key)
}
func (pool *FTEIDM) takeFreeLocked(id uint32) { pool.freeTEIDs.remove(int(id) - 1) }
func (pool *FTEIDM) releaseLocked(id uint32) {
	owner, ok := pool.reservedTEIDs[id]
	if !ok {
		return
	}
	if id <= pool.maximum {
		pool.freeTEIDs.addBack(int(id) - 1)
	}
	delete(pool.reservedTEIDs, id)
	delete(pool.ownerTEIDs[owner], id)
	if len(pool.ownerTEIDs[owner]) == 0 {
		delete(pool.ownerTEIDs, owner)
	}
	delete(pool.leaseEpoch, id)
}
