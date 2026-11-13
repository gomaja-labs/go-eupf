package service

import "sync"

// ReplayBudget accounts for every PFCP endpoint in one resource domain. The
// lock never calls back into connection state, so endpoints can hold their own
// transport locks while reserving capacity here.
type ReplayBudget struct {
	mu             sync.Mutex
	nextEndpoint   uint64
	entries, bytes int
	owners         map[ReplayOwner]replayUsage
}

// ReplayOwner identifies a peer association on one local PFCP endpoint.
type ReplayOwner struct {
	Endpoint uint64 // Process-lifetime identity of the local connection.
	NodeID   string // Peer identity, independent of its source IP addresses.
}

// NewEndpoint assigns a local endpoint identity; zero signals exhaustion.
func (budget *ReplayBudget) NewEndpoint() uint64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.nextEndpoint == ^uint64(0) {
		return 0
	}
	budget.nextEndpoint++
	return budget.nextEndpoint
}

type replayUsage struct{ entries, bytes int }

// Reserve admits a maximum-size response before executing a new request. Fair
// shares identify associations by local endpoint and peer Node ID across
// N4/Sxa/Sxb. Retained outcomes are
// never evicted to admit another request (TS 29.244 V20.1.0 clause 6.4).
func (budget *ReplayBudget) Reserve(owner ReplayOwner, cost, entryLimit, byteLimit int) bool {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	usage, exists := budget.owners[owner]
	holders := len(budget.owners)
	if !exists {
		holders++
	}
	holders = max(1, holders)
	if budget.entries >= entryLimit || cost > byteLimit-budget.bytes || holders > 1 && (usage.entries >= (entryLimit+holders-1)/holders || usage.bytes >= byteLimit/holders) {
		return false
	}
	budget.changeLocked(owner, 1, cost)
	return true
}

// Change atomically replaces a reservation with its actual retained size, or
// releases an expired outcome. Replacing cannot expose a temporary capacity gap.
func (budget *ReplayBudget) Change(owner ReplayOwner, entries, bytes int) {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	budget.changeLocked(owner, entries, bytes)
}
func (budget *ReplayBudget) changeLocked(owner ReplayOwner, entries, bytes int) {
	if budget.owners == nil {
		budget.owners = make(map[ReplayOwner]replayUsage)
	}
	usage := budget.owners[owner]
	usage.entries += entries
	usage.bytes += bytes
	budget.entries += entries
	budget.bytes += bytes
	if usage.entries == 0 {
		delete(budget.owners, owner)
	} else {
		budget.owners[owner] = usage
	}
}

// ReplayBudget returns the shared PFCP replay accounting for this UPF.
func (manager *ResourceManager) ReplayBudget() *ReplayBudget { return &manager.replay }
