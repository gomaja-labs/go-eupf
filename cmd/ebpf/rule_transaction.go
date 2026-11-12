package ebpf

import (
	"errors"
	"fmt"
	"net"

	cilium "github.com/cilium/ebpf"
)

// RuleTransaction journals rule changes through Commit or Rollback. The caller
// holds the control-plane state lock for its lifetime.
type RuleTransaction interface {
	ForwardingPlaneController
	Commit() error
	Rollback() error
}

type ruleTransaction struct {
	ForwardingPlaneController
	objects                                  *BpfObjects
	sessionID                                uint64
	releases                                 []func()
	retired                                  []func() error
	dirty                                    bool
	retiredKey                               bool
	graced                                   bool
	undo                                     []func() error
	allocatedFAR, allocatedQER, allocatedURR []uint32
	newQER, newURR                           map[uint32]bool
	finished                                 bool
	beforeWrite                              func() error
	pdrs                                     map[pdrMutationKey]*pdrMutation
	pdrOrder                                 []*pdrMutation
}

// BeginRuleTransaction serializes control-plane journals without stopping packet
// processing. TS 29.244 V20.1.0 clauses 6.3.2.3 and 6.3.3.3 require a final
// all-or-nothing outcome; they do not require packet-level atomicity across keys.
func (b *BpfObjects) BeginRuleTransaction(sessionID uint64) (RuleTransaction, error) {
	b.ruleMutex.Lock()
	if b.ruleClosed || b.grace == nil {
		b.ruleMutex.Unlock()
		return nil, fmt.Errorf("rule maps are not loaded")
	}
	if b.rulePoison != nil || b.grace.failure() != nil {
		b.ruleMutex.Unlock()
		return nil, fmt.Errorf("rule state requires recovery: %w", errors.Join(b.rulePoison, b.grace.failure()))
	}
	return &ruleTransaction{ForwardingPlaneController: b, objects: b, sessionID: sessionID, newQER: make(map[uint32]bool), newURR: make(map[uint32]bool)}, nil
}

func journalRule[T any](tx *ruleTransaction, m *cilium.Map, key interface{}, change func() error) error {
	if m == tx.objects.PdrMapTeidIp4 || m == tx.objects.PdrMapDownlinkIp4 || m == tx.objects.PdrMapDownlinkIp6 {
		tx.dirty = true
		tx.graced = false
	}
	var previous T
	err := lookupRuleValue(m, key, &previous)
	present := err == nil
	if err != nil && !isKeyAbsent(err) {
		return err
	}
	if tx.beforeWrite != nil {
		if err := tx.beforeWrite(); err != nil {
			return err
		}
	}
	if err := change(); err != nil {
		return err
	}
	tx.undo = append(tx.undo, func() error {
		if present {
			return m.Put(key, &previous)
		}
		err := m.Delete(key)
		if isKeyAbsent(err) {
			return nil
		}
		return err
	})
	return nil
}

func (tx *ruleTransaction) Commit() error {
	if tx.finished {
		return fmt.Errorf("rule transaction already finished")
	}
	if err := tx.publishPDRs(); err != nil {
		return err
	}
	if tx.retiredKey {
		if err := tx.synchronize(); err != nil {
			return err
		}
	}
	tx.objects.grace.retire(tx.retired, tx.graced && !tx.dirty)
	for _, release := range tx.releases {
		release()
	}
	tx.finished = true
	tx.objects.ruleMutex.Unlock()
	return nil
}
func (tx *ruleTransaction) Rollback() error {
	if tx.finished {
		return nil
	}
	var result error
	for i := len(tx.undo) - 1; i >= 0; i-- {
		result = errors.Join(result, tx.undo[i]())
	}
	b := tx.objects
	result = errors.Join(result, b.grace.wait())
	if result == nil {
		for _, id := range tx.allocatedFAR {
			b.ReleaseFAR(id)
		}
		for _, id := range tx.allocatedQER {
			b.ReleaseQER(id)
		}
		for _, id := range tx.allocatedURR {
			b.ReleaseURR(id)
		}
	} else {
		b.rulePoison = result
	}
	tx.finished = true
	b.ruleMutex.Unlock()
	return result
}
func (tx *ruleTransaction) PutPdrUplink(key uint32, info PdrInfo) error {
	return tx.stagePDR(tx.objects.PdrMapTeidIp4, key, info)
}
func (tx *ruleTransaction) PutPdrDownlink(ip net.IP, info PdrInfo) error {
	m, key, err := tx.objects.downlinkRuleMap(ip, info.UEIPv6Mask)
	if err != nil {
		return err
	}
	return tx.stagePDR(m, key, info)
}
func (tx *ruleTransaction) PutDownlinkPdrIp6(ip net.IP, info PdrInfo) error {
	return tx.PutPdrDownlink(ip, info)
}
func (tx *ruleTransaction) UpdatePdrUplink(key uint32, info PdrInfo) error {
	return tx.PutPdrUplink(key, info)
}
func (tx *ruleTransaction) UpdatePdrDownlink(ip net.IP, info PdrInfo) error {
	return tx.PutPdrDownlink(ip, info)
}
func (tx *ruleTransaction) UpdateDownlinkPdrIp6(ip net.IP, info PdrInfo) error {
	return tx.PutPdrDownlink(ip, info)
}
func (tx *ruleTransaction) DeletePdrUplink(key uint32, sessionID uint64, id uint32) error {
	return tx.stagePDRDelete(tx.objects.PdrMapTeidIp4, key, sessionID, id)
}
func (tx *ruleTransaction) DeletePdrDownlink(ip net.IP, sessionID uint64, id uint32) error {
	m, key, err := tx.objects.downlinkMap(ip)
	if err != nil {
		return err
	}
	return tx.stagePDRDelete(m, key, sessionID, id)
}
func (tx *ruleTransaction) DeleteDownlinkPdrIp6(ip net.IP, sessionID uint64, id uint32, prefixLength uint32) error {
	m, key, err := tx.objects.downlinkRuleMap(ip, net.CIDRMask(int(prefixLength), 128))
	if err != nil {
		return err
	}
	return tx.stagePDRDelete(m, key, sessionID, id)
}
func (tx *ruleTransaction) NewFar(info FarInfo) (uint32, error) {
	b := tx.objects
	id, err := tx.GetNextFAR()
	if err != nil {
		return 0, err
	}
	err = tx.UpdateFar(id, info)
	if err != nil {
		b.ReleaseFAR(id)
		return 0, err
	}
	return id, nil
}
func (tx *ruleTransaction) NewQer(info QerInfo) (uint32, error) {
	b := tx.objects
	id, err := tx.GetNextQER()
	if err != nil {
		return 0, err
	}
	value := qerMapValue(info)
	err = journalRule[IpEntrypointQerInfo](tx, b.QerMap, id, func() error { return b.QerMap.Put(id, &value) })
	if err != nil {
		b.ReleaseQER(id)
		return 0, err
	}
	return id, nil
}
func (tx *ruleTransaction) NewUrr(info UrrInfo) (uint32, error) {
	b := tx.objects
	id, err := tx.GetNextURR()
	if err != nil {
		return 0, err
	}
	err = journalRule[IpEntrypointUrrInfo](tx, b.UrrMap, id, func() error {
		return b.UrrMap.Put(id, &IpEntrypointUrrInfo{Ul: info.UplinkVolume, Dl: info.DownlinkVolume})
	})
	if err != nil {
		b.ReleaseURR(id)
		return 0, err
	}
	return id, nil
}
func (tx *ruleTransaction) UpdateFar(id uint32, info FarInfo) error {
	return journalRule[IpEntrypointFarInfo](tx, tx.objects.FarMap, id, func() error { return tx.objects.UpdateFar(id, info) })
}
func (tx *ruleTransaction) UpdateQer(id uint32, info QerInfo) error {
	if tx.newQER[id] {
		value := qerMapValue(info)
		return journalRule[IpEntrypointQerInfo](tx, tx.objects.QerMap, id, func() error { return tx.objects.QerMap.Put(id, &value) })
	}
	return journalRule[IpEntrypointQerInfo](tx, tx.objects.QerMap, id, func() error { return tx.objects.UpdateQer(id, info) })
}
func (tx *ruleTransaction) UpdateUrr(id uint32, info UrrInfo) error {
	if tx.newURR[id] {
		value := IpEntrypointUrrInfo{}
		return journalRule[IpEntrypointUrrInfo](tx, tx.objects.UrrMap, id, func() error { return tx.objects.UrrMap.Put(id, &value) })
	}
	return tx.objects.UpdateUrr(id, info)
}
func (tx *ruleTransaction) DeleteFar(id uint32) error {
	if id == 0 {
		return fmt.Errorf("reserved FAR slot")
	}
	if err := tx.detach(1, id); err != nil {
		return err
	}
	// The detached slot remains reserved until every old reader has returned.
	// Clearing an unreachable value is reclamation, not a rule-plan write.
	tx.retired = append(tx.retired, func() error {
		if err := tx.objects.FarMap.Put(id, &IpEntrypointFarInfo{}); err != nil {
			return err
		}
		tx.objects.ReleaseFAR(id)
		return nil
	})
	return nil
}
func (tx *ruleTransaction) DeleteQer(id uint32) error {
	if id == 0 {
		return fmt.Errorf("reserved QER slot")
	}
	if err := tx.detach(2, id); err != nil {
		return err
	}
	tx.retired = append(tx.retired, func() error {
		if err := tx.objects.QerMap.Put(id, &IpEntrypointQerInfo{}); err != nil {
			return err
		}
		tx.objects.ReleaseQER(id)
		return nil
	})
	return nil
}

func (tx *ruleTransaction) DeleteUrr(id uint32) (UrrInfo, error) {
	if id == 0 {
		return UrrInfo{}, fmt.Errorf("reserved URR slot")
	}
	if err := tx.detach(3, id); err != nil {
		return UrrInfo{}, err
	}
	result, err := tx.GetUrr(id)
	if err != nil {
		return UrrInfo{}, err
	}
	err = journalRule[IpEntrypointUrrInfo](tx, tx.objects.UrrMap, id, func() error { return tx.objects.UrrMap.Put(id, &IpEntrypointUrrInfo{}) })
	if err == nil {
		tx.releases = append(tx.releases, func() { tx.objects.ReleaseURR(id) })
	}
	return result, err
}
func (tx *ruleTransaction) detach(kind uint8, id uint32) error {
	b := tx.objects
	return errors.Join(detachRuleMap[uint32](tx, b.PdrMapTeidIp4, kind, id), detachRuleMap[[4]byte](tx, b.PdrMapDownlinkIp4, kind, id), detachRuleMap[IpEntrypointIpv6PdrKey](tx, b.PdrMapDownlinkIp6, kind, id))
}
func detachRuleMap[K comparable](tx *ruleTransaction, m *cilium.Map, kind uint8, id uint32) error {
	var key K
	var bucket IpEntrypointPdrInfo
	iter := m.Iterate()
	for iter.Next(&key, &bucket) {
		if bucket.SessionId != tx.sessionID {
			continue
		}
		if _, err := tx.pdrDraft(m, key); err != nil {
			return err
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, draft := range tx.pdrOrder {
		if draft.m != m {
			continue
		}
		changed := false
		for i := 0; i < len(draft.entries); i++ {
			for variant := 0; variant < 2; variant++ {
				pdr := &draft.entries[i].Pdr
				if variant == 1 {
					pdr = &draft.entries[i].ReturnPdr
				}
				switch kind {
				case 1:
					if pdr.FarId == id {
						pdr.FarId = 0
						changed = true
					}
				case 2:
					n := 0
					for _, ref := range pdr.QerId[:min(int(pdr.QerCount), MaxQERsPerPDR)] {
						if ref != id {
							pdr.QerId[n] = ref
							n++
						} else {
							changed = true
						}
					}
					clear(pdr.QerId[n:])
					pdr.QerCount = uint8(n)
				case 3:
					n := 0
					for _, ref := range pdr.UrrId {
						if ref != id && ref != 0 {
							pdr.UrrId[n] = ref
							n++
						} else if ref == id {
							changed = true
						}
					}
					clear(pdr.UrrId[n:])
				}
			}
		}
		draft.changed = draft.changed || changed
	}
	return nil
}

func (tx *ruleTransaction) GetNextFAR() (uint32, error) {
	id, err := tx.objects.GetNextFAR()
	if err == nil {
		tx.allocatedFAR = append(tx.allocatedFAR, id)
	}
	return id, err
}
func (tx *ruleTransaction) GetNextQER() (uint32, error) {
	id, err := tx.objects.GetNextQER()
	if err == nil {
		tx.newQER[id] = true
		tx.allocatedQER = append(tx.allocatedQER, id)
	}
	return id, err
}
func (tx *ruleTransaction) GetNextURR() (uint32, error) {
	id, err := tx.objects.GetNextURR()
	if err == nil {
		tx.newURR[id] = true
		tx.allocatedURR = append(tx.allocatedURR, id)
	}
	return id, err
}

// LockRuleSnapshot excludes an in-progress control-plane map journal while a
// diagnostic reader copies its values. It must not acquire the PFCP state lock.
func (b *BpfObjects) LockRuleSnapshot() func() { b.ruleMutex.Lock(); return b.ruleMutex.Unlock }

func (tx *ruleTransaction) ResetUrr(id uint32) error {
	if err := tx.synchronize(); err != nil {
		return err
	}
	return journalRule[IpEntrypointUrrInfo](tx, tx.objects.UrrMap, id, func() error { return tx.objects.ResetUrr(id) })
}

func (tx *ruleTransaction) synchronize() error {
	if err := tx.publishPDRs(); err != nil {
		return err
	}
	if tx.graced && !tx.dirty {
		return nil
	}
	if err := tx.objects.grace.wait(); err != nil {
		return err
	}
	tx.dirty = false
	tx.graced = true
	return nil
}
func (tx *ruleTransaction) GetUrr(id uint32) (UrrInfo, error) {
	if err := tx.synchronize(); err != nil {
		return UrrInfo{}, err
	}
	return tx.objects.GetUrr(id)
}
func (tx *ruleTransaction) DetachRule(kind uint8, id uint32) error { return tx.detach(kind, id) }
func (b *BpfObjects) DetachRule(uint8, uint32) error {
	return fmt.Errorf("rule detachment requires a transaction")
}

func (tx *ruleTransaction) SynchronizeRules() error { return tx.synchronize() }
func (b *BpfObjects) SynchronizeRules() error       { return b.grace.wait() }
