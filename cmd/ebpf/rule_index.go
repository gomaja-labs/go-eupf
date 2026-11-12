package ebpf

import cilium "github.com/cilium/ebpf"

// ruleKeyIndex is the control-plane mirror of published lookup-key ownership.
// ruleMutex owns it, like map publication. Preflight and detachment touch only
// the requesting session's keys; packet readers never consult this index.
type ruleKeyIndex struct {
	keys       map[pdrMutationKey]uint64
	owners     map[uint64]map[pdrMutationKey]bool
	counts     map[*cilium.Map]uint64
	capacities map[*cilium.Map]uint64
	prefixes   *rulePrefixNode
}
type rulePrefixNode struct {
	child        [2]*rulePrefixNode
	assigned     bool
	owner        uint64
	count        int
	summaryOwner uint64
	mixed        bool
}

func (node *rulePrefixNode) recompute() {
	node.count = 0
	node.mixed = false
	add := func(count int, owner uint64, mixed bool) {
		if count == 0 {
			return
		}
		if node.count > 0 && node.summaryOwner != owner {
			node.mixed = true
		}
		node.summaryOwner = owner
		node.mixed = node.mixed || mixed
		node.count += count
	}
	if node.assigned {
		add(1, node.owner, false)
	}
	for _, child := range node.child {
		if child != nil {
			add(child.count, child.summaryOwner, child.mixed)
		}
	}
}
func (node *rulePrefixNode) set(address [16]byte, bits int, owner uint64, present bool) {
	path := []*rulePrefixNode{node}
	for depth := 0; depth < bits; depth++ {
		bit := (address[depth/8] >> uint(7-depth%8)) & 1
		if node.child[bit] == nil {
			if !present {
				return
			}
			node.child[bit] = &rulePrefixNode{}
		}
		node = node.child[bit]
		path = append(path, node)
	}
	node.assigned, node.owner = present, owner
	for i := len(path) - 1; i >= 0; i-- {
		path[i].recompute()
		for bit, child := range path[i].child {
			if child != nil && child.count == 0 {
				path[i].child[bit] = nil
			}
		}
	}
}
func (node *rulePrefixNode) conflicts(address [16]byte, bits int, owner uint64) bool {
	for depth := 0; node != nil; depth++ {
		if node.assigned && node.owner != owner {
			return true
		}
		if depth == bits {
			return node.count > 0 && (node.mixed || node.summaryOwner != owner)
		}
		node = node.child[(address[depth/8]>>uint(7-depth%8))&1]
	}
	return false
}
func (node *rulePrefixNode) distinctOverlap(address [16]byte, bits int) bool {
	for depth := 0; node != nil; depth++ {
		if depth == bits {
			count := node.count
			if node.assigned {
				count--
			}
			return count > 0
		}
		if node.assigned {
			return true
		}
		node = node.child[(address[depth/8]>>uint(7-depth%8))&1]
	}
	return false
}
func (b *BpfObjects) recordPDRKey(m *cilium.Map, key interface{}, owner uint64, present bool) {
	index := &b.ruleKeys
	if index.keys == nil {
		index.keys = make(map[pdrMutationKey]uint64)
		index.owners = make(map[uint64]map[pdrMutationKey]bool)
		index.counts = make(map[*cilium.Map]uint64)
		index.capacities = make(map[*cilium.Map]uint64)
		index.prefixes = &rulePrefixNode{}
	}
	k := pdrMutationKey{m, key}
	if previous, exists := index.keys[k]; exists {
		delete(index.owners[previous], k)
		if len(index.owners[previous]) == 0 {
			delete(index.owners, previous)
		}
		delete(index.keys, k)
		index.counts[m]--
	}
	if present {
		index.keys[k] = owner
		index.counts[m]++
		if index.owners[owner] == nil {
			index.owners[owner] = make(map[pdrMutationKey]bool)
		}
		index.owners[owner][k] = true
	}
	if prefix, ok := key.(IpEntrypointIpv6PdrKey); ok {
		index.prefixes.set(prefix.Address, int(prefix.PrefixLength), owner, present)
	}
}
