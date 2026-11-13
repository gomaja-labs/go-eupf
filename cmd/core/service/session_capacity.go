package service

import "fmt"

// SetSessionCapacity configures the shared admission bound before use. Repeating
// the same value permits multiple PFCP endpoints to share one resource manager.
func (manager *ResourceManager) SetSessionCapacity(maximum uint32) error {
	if maximum == 0 || maximum > MaxResourcePoolSize {
		return fmt.Errorf("session capacity must be between 1 and %d", MaxResourcePoolSize)
	}
	manager.sessionsMu.Lock()
	defer manager.sessionsMu.Unlock()
	if manager.sessionMaximum == maximum {
		return nil
	}
	if len(manager.sessions) > 0 {
		return fmt.Errorf("cannot change session capacity while contexts are reserved")
	}
	manager.sessionMaximum = maximum
	return nil
}

// AdmitSession reserves one context across every endpoint and association.
// The reservation lasts through rule retirement, including rejected requests
// that published temporary rules. TS 29.244 V20.1.0 table 8.2.1-1 specifies
// Cause 75 when the UP function lacks resources for another PFCP session.
func (manager *ResourceManager) AdmitSession(id uint64) error {
	if manager == nil {
		return ErrResourceExhausted
	}
	if id == 0 {
		return fmt.Errorf("session ID must be nonzero")
	}
	manager.sessionsMu.Lock()
	defer manager.sessionsMu.Unlock()
	if _, exists := manager.sessions[id]; exists {
		return ErrResourceCollision
	}
	maximum := manager.sessionMaximum
	if maximum == 0 {
		maximum = 65535
	}
	if len(manager.sessions) >= int(maximum) {
		return ErrResourceExhausted
	}
	if manager.sessions == nil {
		manager.sessions = make(map[uint64]struct{})
	}
	manager.sessions[id] = struct{}{}
	return nil
}

// ReleaseSession returns an admission only after its transaction and resource
// reclamation both succeed. Repeated completion cannot release another context.
func (manager *ResourceManager) ReleaseSession(id uint64) {
	if manager == nil {
		return
	}
	manager.sessionsMu.Lock()
	delete(manager.sessions, id)
	manager.sessionsMu.Unlock()
}

// HasTEID reports an existing active or retiring reservation without changing
// the pool. It also covers predecessor generations and explicit legacy TEIDs.
func (pool *FTEIDM) HasTEID(id uint32) bool {
	if pool == nil {
		return false
	}
	if pool.parent != nil {
		return pool.parent.HasTEID(id)
	}
	pool.RLock()
	defer pool.RUnlock()
	_, reserved := pool.reservedTEIDs[id]
	return reserved
}
