package service

import "net"

// reservationTrie indexes IPv6 hosts and prefixes in at most 128 steps. Claims
// at ancestors and descendant owner summaries avoid scanning other sessions.
type reservationTrie struct {
	children   [2]*reservationTrie
	claims     map[string]uint64
	claimOwner uint64
	count      int
	owner      uint64
	mixed      bool
}

func (node *reservationTrie) set(ip net.IP, bits int, key string, owner uint64, present bool) {
	address := ip.To16()
	if address == nil {
		return
	}
	path := []*reservationTrie{node}
	for depth := 0; depth < bits; depth++ {
		bit := (address[depth/8] >> uint(7-depth%8)) & 1
		if node.children[bit] == nil {
			if !present {
				return
			}
			node.children[bit] = &reservationTrie{}
		}
		node = node.children[bit]
		path = append(path, node)
	}
	if present {
		if node.claims == nil {
			node.claims = make(map[string]uint64)
		}
		node.claims[key] = owner
		node.claimOwner = owner
	} else {
		delete(node.claims, key)
	}
	for i := len(path) - 1; i >= 0; i-- {
		n := path[i]
		n.count = 0
		n.mixed = false
		add := func(count int, owner uint64, mixed bool) {
			if count == 0 {
				return
			}
			if n.count > 0 && n.owner != owner {
				n.mixed = true
			}
			n.owner = owner
			n.mixed = n.mixed || mixed
			n.count += count
		}
		add(len(n.claims), n.claimOwner, false)
		for bit, child := range n.children {
			if child == nil {
				continue
			}
			if child.count == 0 {
				n.children[bit] = nil
			} else {
				add(child.count, child.owner, child.mixed)
			}
		}
	}
}
func (node *reservationTrie) conflicts(ip net.IP, bits int, owner uint64) bool {
	address := ip.To16()
	if address == nil {
		return false
	}
	for depth := 0; node != nil; depth++ {
		if len(node.claims) > 0 && node.claimOwner != owner {
			return true
		}
		if depth == bits {
			return node.count > 0 && (node.mixed || node.owner != owner)
		}
		node = node.children[(address[depth/8]>>uint(7-depth%8))&1]
	}
	return false
}
