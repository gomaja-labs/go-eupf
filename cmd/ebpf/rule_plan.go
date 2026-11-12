package ebpf

import (
	"fmt"
	"net"
	"slices"

	cilium "github.com/cilium/ebpf"
)

// PDRKey describes the lookup keys of one PDR in the final session draft.
// UE addresses in a TEID PDR are constraints, rather than N6 lookup keys.
type PDRKey struct {
	ID, TEID   uint32
	IPv4, IPv6 net.IP
	IPv6Mask   net.IPMask
}

// PDRPlanError identifies the PDR whose key cannot be provisioned.
type PDRPlanError struct {
	ID  uint32
	Err error
}

func (e *PDRPlanError) Error() string { return fmt.Sprintf("PDR %d key: %v", e.ID, e.Err) }
func (e *PDRPlanError) Unwrap() error { return e.Err }

type plannedPDRKey[K comparable] struct {
	key K
	id  uint32
}

// CheckPDRPlan validates ownership, prefix intersections and every key bound
// before slot reservation or map writes. The caller holds the rule transaction.
// TS 29.244 V20.1.0 clauses 5.2.1 and 6.3.3.3.
func (b *BpfObjects) CheckPDRPlan(sessionID uint64, keys []PDRKey) error {
	keys = slices.Clone(keys)
	slices.SortFunc(keys, func(a, c PDRKey) int {
		if a.ID < c.ID {
			return -1
		}
		if a.ID > c.ID {
			return 1
		}
		return 0
	})
	var uplink []plannedPDRKey[uint32]
	var ipv4 []plannedPDRKey[[4]byte]
	var ipv6 []plannedPDRKey[IpEntrypointIpv6PdrKey]
	for _, pdr := range keys {
		if pdr.TEID != 0 {
			uplink = append(uplink, plannedPDRKey[uint32]{pdr.TEID, pdr.ID})
			continue
		}
		if pdr.IPv4 != nil {
			ip := pdr.IPv4.To4()
			if ip == nil {
				return &PDRPlanError{pdr.ID, fmt.Errorf("invalid IPv4 key")}
			}
			var key [4]byte
			copy(key[:], ip)
			ipv4 = append(ipv4, plannedPDRKey[[4]byte]{key, pdr.ID})
		}
		if pdr.IPv6 != nil {
			if pdr.IPv6.To4() != nil || pdr.IPv6.To16() == nil {
				return &PDRPlanError{pdr.ID, fmt.Errorf("invalid IPv6 key")}
			}
			_, key, err := b.downlinkRuleMap(pdr.IPv6, pdr.IPv6Mask)
			if err != nil {
				return &PDRPlanError{pdr.ID, err}
			}
			ipv6 = append(ipv6, plannedPDRKey[IpEntrypointIpv6PdrKey]{key.(IpEntrypointIpv6PdrKey), pdr.ID})
		}
	}
	if err := checkPDRMapPlan(b.PdrMapTeidIp4, sessionID, uplink, nil); err != nil {
		return err
	}
	if err := checkPDRMapPlan(b.PdrMapDownlinkIp4, sessionID, ipv4, nil); err != nil {
		return err
	}
	overlap := func(a, c IpEntrypointIpv6PdrKey) bool {
		left := net.IPNet{IP: net.IP(a.Address[:]), Mask: net.CIDRMask(int(a.PrefixLength), 128)}
		right := net.IPNet{IP: net.IP(c.Address[:]), Mask: net.CIDRMask(int(c.PrefixLength), 128)}
		return left.Contains(right.IP) || right.Contains(left.IP)
	}
	return checkPDRMapPlan(b.PdrMapDownlinkIp6, sessionID, ipv6, overlap)
}
func checkPDRMapPlan[K comparable](m *cilium.Map, sessionID uint64, planned []plannedPDRKey[K], overlap func(K, K) bool) error {
	if len(planned) == 0 {
		return nil
	}
	counts := make(map[K]int)
	owners := make(map[K]uint32)
	for _, entry := range planned {
		counts[entry.key]++
		if counts[entry.key] > MaxPDRsPerKey {
			return &PDRPlanError{entry.id, ErrRuleCapacity}
		}
		if counts[entry.key] == 1 && overlap != nil {
			for existing := range owners {
				if existing != entry.key && overlap(existing, entry.key) {
					return &PDRPlanError{entry.id, ErrUnsupportedRuleContent}
				}
			}
		}
		owners[entry.key] = entry.id
	}
	var key K
	var value IpEntrypointPdrInfo
	other := uint64(0)
	iterator := m.Iterate()
	for iterator.Next(&key, &value) {
		if value.SessionId == sessionID {
			continue
		}
		other++
		if id, exists := owners[key]; exists {
			return &PDRPlanError{id, ErrKeyOwned}
		}
		if overlap != nil {
			for candidate, id := range owners {
				if overlap(key, candidate) {
					return &PDRPlanError{id, ErrKeyOwned}
				}
			}
		}
	}
	if err := iterator.Err(); err != nil {
		return fmt.Errorf("read PDR map for validation: %w", err)
	}
	info, err := m.Info()
	if err != nil {
		return err
	}
	if other+uint64(len(counts)) > uint64(info.MaxEntries) {
		return &PDRPlanError{planned[len(planned)-1].id, ErrRuleCapacity}
	}
	return nil
}
