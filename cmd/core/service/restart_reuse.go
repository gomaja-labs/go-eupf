package service

import "time"

// HoldAutomaticIPv4Until reserves the startup restoration window for
// explicit RESTI UE addresses (TS 23.527 V20.0.0 clause 4.3.2).
func (manager *ResourceManager) HoldAutomaticIPv4Until(deadline time.Time) {
	if pool := manager.IPAM; pool != nil {
		pool.Lock()
		pool.allocateAfter = deadline
		pool.Unlock()
	}
}
