package ebpf

import (
	"errors"
	"fmt"
	"net"
	"time"

	cilium "github.com/cilium/ebpf"
)

// RuleTransaction quiesces rule users until Commit or Rollback. The caller
// holds the control-plane state lock for its lifetime.
type RuleTransaction interface {
	ForwardingPlaneController
	Commit() error
	Rollback() error
}

type ruleTransaction struct {
	ForwardingPlaneController
	objects        *BpfObjects
	sessionID      uint64
	releases       []func()
	undo           []func() error
	far, qer, urr  *IdTracker
	newQER, newURR map[uint32]bool
	finished       bool
	beforeWrite    func() error
}

func (b *BpfObjects) setRuleGate(closed bool) error {
	packet := make([]byte, 64)
	if closed {
		packet[0] = 1
	}
	action, _, err := b.UpfRuleControl.Test(packet)
	if err != nil {
		return fmt.Errorf("set rule gate: %w", err)
	}
	if action != 2 {
		return fmt.Errorf("rule gate control returned %d", action)
	}
	return nil
}

// BeginRuleTransaction blocks new user-plane rule users and drains admitted
// program invocations. Non-user-plane traffic keeps its ordinary path. A local
// tunnel tail call releases its reference before entering the next invocation.
// TS 29.244 V20.1.0 clauses 6.3.3.3 and 5.2.2.3.1.
func (b *BpfObjects) BeginRuleTransaction(sessionID uint64) (RuleTransaction, error) {
	b.ruleMutex.Lock()
	if b.rulePoison != nil {
		b.ruleMutex.Unlock()
		return nil, fmt.Errorf("rule state requires recovery: %w", b.rulePoison)
	}
	if err := b.setRuleGate(true); err != nil {
		b.ruleMutex.Unlock()
		return nil, err
	}
	deadline := time.Now().Add(time.Second)
	for {
		var gate IpEntrypointRuleGate
		if err := b.RuleGate.LookupWithFlags(uint32(0), &gate, cilium.LookupLock); err != nil {
			openErr := b.setRuleGate(false)
			b.ruleMutex.Unlock()
			return nil, errors.Join(err, openErr)
		}
		if gate.Active == 0 {
			break
		}
		if time.Now().After(deadline) {
			openErr := b.setRuleGate(false)
			b.ruleMutex.Unlock()
			return nil, errors.Join(fmt.Errorf("rule users did not quiesce"), openErr)
		}
		time.Sleep(time.Millisecond)
	}
	b.farMutex.Lock()
	defer b.farMutex.Unlock()
	b.qerMutex.Lock()
	defer b.qerMutex.Unlock()
	b.urrMutex.Lock()
	defer b.urrMutex.Unlock()
	clone := func(t *IdTracker) *IdTracker { return &IdTracker{bitmap: t.bitmap.Clone(), maxSize: t.maxSize} }
	return &ruleTransaction{ForwardingPlaneController: b, objects: b, sessionID: sessionID, newQER: make(map[uint32]bool), newURR: make(map[uint32]bool), far: clone(b.farIdTracker), qer: clone(b.qerIdTracker), urr: clone(b.urrIdTracker)}, nil
}

func journalRule[T any](tx *ruleTransaction, m *cilium.Map, key interface{}, change func() error) error {
	var previous T
	err := m.Lookup(key, &previous)
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
	if err := tx.objects.setRuleGate(false); err != nil {
		return err
	}
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
	b.farMutex.Lock()
	b.farIdTracker = tx.far
	b.farMutex.Unlock()
	b.qerMutex.Lock()
	b.qerIdTracker = tx.qer
	b.qerMutex.Unlock()
	b.urrMutex.Lock()
	b.urrIdTracker = tx.urr
	b.urrMutex.Unlock()
	// A failed restore must remain closed; reopening would expose partial
	// state. The error is returned to the control plane for explicit recovery.
	if result == nil {
		result = b.setRuleGate(false)
	}
	if result != nil {
		b.rulePoison = result
	}
	tx.finished = true
	b.ruleMutex.Unlock()
	return result
}
func (tx *ruleTransaction) PutPdrUplink(key uint32, info PdrInfo) error {
	return journalRule[IpEntrypointPdrInfo](tx, tx.objects.PdrMapTeidIp4, key, func() error { return tx.objects.PutPdrUplink(key, info) })
}
func (tx *ruleTransaction) PutPdrDownlink(ip net.IP, info PdrInfo) error {
	m, key, err := tx.objects.downlinkRuleMap(ip, info.UEIPv6Mask)
	if err != nil {
		return err
	}
	return journalRule[IpEntrypointPdrInfo](tx, m, key, func() error { return tx.objects.PutPdrDownlink(ip, info) })
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
	return journalRule[IpEntrypointPdrInfo](tx, tx.objects.PdrMapTeidIp4, key, func() error { return tx.objects.DeletePdrUplink(key, sessionID, id) })
}
func (tx *ruleTransaction) DeletePdrDownlink(ip net.IP, sessionID uint64, id uint32) error {
	m, key, err := tx.objects.downlinkMap(ip)
	if err != nil {
		return err
	}
	return journalRule[IpEntrypointPdrInfo](tx, m, key, func() error { return tx.objects.DeletePdrDownlink(ip, sessionID, id) })
}
func (tx *ruleTransaction) DeleteDownlinkPdrIp6(ip net.IP, sessionID uint64, id uint32, prefixLength uint32) error {
	m, key, err := tx.objects.downlinkRuleMap(ip, net.CIDRMask(int(prefixLength), 128))
	if err != nil {
		return err
	}
	return journalRule[IpEntrypointPdrInfo](tx, m, key, func() error { return tx.objects.DeleteDownlinkPdrIp6(ip, sessionID, id, prefixLength) })
}
func (tx *ruleTransaction) NewFar(info FarInfo) (uint32, error) {
	b := tx.objects
	id, err := b.GetNextFAR()
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
	id, err := b.GetNextQER()
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
	id, err := b.GetNextURR()
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
	return journalRule[IpEntrypointUrrInfo](tx, tx.objects.UrrMap, id, func() error { return tx.objects.UpdateUrr(id, info) })
}
func (tx *ruleTransaction) DeleteFar(id uint32) error {
	if id == 0 {
		return fmt.Errorf("reserved FAR slot")
	}
	if err := tx.detach(1, id); err != nil {
		return err
	}
	err := journalRule[IpEntrypointFarInfo](tx, tx.objects.FarMap, id, func() error { return tx.objects.FarMap.Put(id, &IpEntrypointFarInfo{}) })
	if err == nil {
		tx.releases = append(tx.releases, func() { tx.objects.ReleaseFAR(id) })
	}
	return err
}
func (tx *ruleTransaction) DeleteQer(id uint32) error {
	if id == 0 {
		return fmt.Errorf("reserved QER slot")
	}
	if err := tx.detach(2, id); err != nil {
		return err
	}
	err := journalRule[IpEntrypointQerInfo](tx, tx.objects.QerMap, id, func() error { return tx.objects.QerMap.Put(id, &IpEntrypointQerInfo{}) })
	if err == nil {
		tx.releases = append(tx.releases, func() { tx.objects.ReleaseQER(id) })
	}
	return err
}
func (tx *ruleTransaction) DeleteUrr(id uint32) (UrrInfo, error) {
	if id == 0 {
		return UrrInfo{}, fmt.Errorf("reserved URR slot")
	}
	if err := tx.detach(3, id); err != nil {
		return UrrInfo{}, err
	}
	result, err := tx.objects.GetUrr(id)
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
		changed := false
		for i := 0; i < int(min(bucket.Count, uint32(MaxPDRsPerKey))); i++ {
			for variant := 0; variant < 2; variant++ {
				pdr := &bucket.Entries[i].Pdr
				if variant == 1 {
					pdr = &bucket.Entries[i].ReturnPdr
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
		if changed {
			savedKey := key
			value := bucket
			if err := journalRule[IpEntrypointPdrInfo](tx, m, savedKey, func() error { return m.Put(savedKey, &value) }); err != nil {
				return err
			}
		}
	}
	return iter.Err()
}

func (tx *ruleTransaction) GetNextFAR() (uint32, error) { return tx.objects.GetNextFAR() }
func (tx *ruleTransaction) GetNextQER() (uint32, error) {
	id, err := tx.objects.GetNextQER()
	if err == nil {
		tx.newQER[id] = true
	}
	return id, err
}
func (tx *ruleTransaction) GetNextURR() (uint32, error) {
	id, err := tx.objects.GetNextURR()
	if err == nil {
		tx.newURR[id] = true
	}
	return id, err
}

// LockRuleSnapshot excludes an in-progress control-plane map journal while a
// diagnostic reader copies its values. It must not acquire the PFCP state lock.
func (b *BpfObjects) LockRuleSnapshot() func() { b.ruleMutex.Lock(); return b.ruleMutex.Unlock }

func (tx *ruleTransaction) ResetUrr(id uint32) error {
	return journalRule[IpEntrypointUrrInfo](tx, tx.objects.UrrMap, id, func() error { return tx.objects.ResetUrr(id) })
}
