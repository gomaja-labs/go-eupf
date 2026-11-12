// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package service

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/korylprince/ipnetgen"
)

type ResourceManager struct {
	IPAM   *IPAM
	FTEIDM *FTEIDM
}

// MaxResourcePoolSize bounds each eagerly materialized resource pool to one
// million entries. IPv4 pools exclude their network address. IPv6 allocation
// requires a prefix allocator and is not supported by this address allocator.
const MaxResourcePoolSize = 1 << 20

type FTEIDM struct {
	freeTEIDs []uint32
	busyTEIDs map[uint64]map[uint32]uint32 // map[seID]map[pdrID]teid
	sync.RWMutex
}

type IPAM struct {
	freeIPs []net.IP
	busyIPs map[uint64]net.IP
	sync.RWMutex
}

func NewResourceManager(ipRange string, teidRange uint32) (*ResourceManager, error) {
	// Validate cardinality before enumerating. In particular uint32's maximum
	// would wrap the TEID loop, and IPv6 /64 would enumerate 2^64 addresses.
	if teidRange > MaxResourcePoolSize {
		return nil, fmt.Errorf("fteid_pool %d exceeds limit %d", teidRange, MaxResourcePoolSize)
	}
	if ipRange != "" {
		_, prefix, err := net.ParseCIDR(ipRange)
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

	var ipam IPAM
	var fteidm FTEIDM

	if ipRange != "" {
		ipGenerator, err := ipnetgen.New(ipRange)
		if err != nil {
			return nil, err
		}
		ipGenerator.Next() //Skip first 0-IP

		freeIPs := make([]net.IP, 0, 1024)
		for ip := ipGenerator.Next(); ip != nil; ip = ipGenerator.Next() {
			freeIPs = append(freeIPs, ip)
		}

		ipam = IPAM{
			freeIPs: freeIPs,
			busyIPs: make(map[uint64]net.IP),
		}
	}

	if teidRange != 0 {
		freeTEIDs := make([]uint32, 0, 10000)
		busyTEIDs := make(map[uint64]map[uint32]uint32)

		var teid uint32

		for teid = 1; teid <= teidRange; teid++ {
			freeTEIDs = append(freeTEIDs, teid)
		}

		fteidm = FTEIDM{
			freeTEIDs: freeTEIDs,
			busyTEIDs: busyTEIDs,
		}
	}

	return &ResourceManager{
		IPAM:   &ipam,
		FTEIDM: &fteidm,
	}, nil
}

func (ipam *IPAM) AllocateIP(key uint64) (net.IP, error) {
	ipam.Lock()
	defer ipam.Unlock()

	// Keep the session's existing address when several PDRs request it.
	// TS 29.244 V20.1.0 clause 5.21.3.1.
	if ip, ok := ipam.busyIPs[key]; ok {
		return append(net.IP(nil), ip...), nil
	}

	if len(ipam.freeIPs) > 0 {
		ip := ipam.freeIPs[0]
		ipam.freeIPs = ipam.freeIPs[1:]
		ipam.busyIPs[key] = ip
		return append(net.IP(nil), ip...), nil
	} else {
		return nil, errors.New("no free ip available")
	}
}

func (ipam *FTEIDM) AllocateTEID(seID uint64, pdrID uint32) (uint32, error) {
	ipam.Lock()
	defer ipam.Unlock()

	// A retry for an already allocated PDR must not consume another F-TEID.
	// TS 29.244 V20.1.0 clause 5.5.3.
	if teid, ok := ipam.busyTEIDs[seID][pdrID]; ok {
		return teid, nil
	}

	if len(ipam.freeTEIDs) > 0 {
		teid := ipam.freeTEIDs[0]
		ipam.freeTEIDs = ipam.freeTEIDs[1:]
		if _, ok := ipam.busyTEIDs[seID]; !ok {
			pdr := make(map[uint32]uint32)
			pdr[pdrID] = teid
			ipam.busyTEIDs[seID] = pdr
		} else {
			ipam.busyTEIDs[seID][pdrID] = teid
		}
		return teid, nil
	} else {
		return 0, errors.New("no free TEID available")
	}
}

func (ipam *IPAM) ReleaseIP(seID uint64) {
	ipam.Lock()
	defer ipam.Unlock()
	if ip, ok := ipam.busyIPs[seID]; ok {
		ipam.freeIPs = append(ipam.freeIPs, ip)
		delete(ipam.busyIPs, seID)
	}
}

func (fteidm *FTEIDM) ReleaseTEID(seID uint64) {
	fteidm.Lock()
	defer fteidm.Unlock()

	if teid, ok := fteidm.busyTEIDs[seID]; ok {
		for _, t := range teid {
			fteidm.freeTEIDs = append(fteidm.freeTEIDs, t)
		}
		delete(fteidm.busyTEIDs, seID)
	}
}
