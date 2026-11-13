package service

import "time"

// HoldAutomaticAllocationsUntil reserves the startup restoration window for
// explicit RESTI resources (TS 23.527 V20.0.0 clause 4.3.2).
func (manager *ResourceManager) HoldAutomaticAllocationsUntil(deadline time.Time) {
	if pool := manager.IPAM; pool != nil {
		pool.Lock()
		pool.allocateAfter = deadline
		pool.Unlock()
	}
	if pool := manager.FTEIDM; pool != nil {
		pool.Lock()
		pool.allocateAfter = deadline
		pool.Unlock()
	}
}
