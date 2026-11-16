package ebpf

import (
	"fmt"
	"sort"

	cilium "github.com/cilium/ebpf"
)

type pdrImage struct {
	owner           uint64
	entries         []IpEntrypointPdrEntry
	slot            uint32
	hasNotification bool
}

// entries belongs to a completed draft and is immutable after publication.
// Retain only populated entries, rather than the kernel's fixed-capacity image.
func publicationImage(owner uint64, entries []IpEntrypointPdrEntry, slot uint32) pdrImage {
	image := pdrImage{owner: owner, entries: entries, slot: slot}
	for i := range entries {
		image.hasNotification = image.hasNotification || entries[i].Notify != 0
	}
	return image
}

type pdrMutationKey struct {
	m   *cilium.Map
	key interface{}
}
type pdrMutation struct {
	pdrMutationKey
	owner        uint64
	entries      []IpEntrypointPdrEntry
	changed      bool
	previous     pdrImage
	present      bool
	previousSlot uint32
}

func (b *BpfObjects) copyPDRImage(entries []IpEntrypointPdrEntry) []IpEntrypointPdrEntry {
	for i := len(b.freePDRImages) - 1; i >= 0; i-- {
		if cap(b.freePDRImages[i]) >= len(entries) {
			out := b.freePDRImages[i][:len(entries)]
			last := len(b.freePDRImages) - 1
			b.freePDRImages[i] = b.freePDRImages[last]
			b.freePDRImages[last] = nil
			b.freePDRImages = b.freePDRImages[:last]
			copy(out, entries)
			return out
		}
	}
	return append([]IpEntrypointPdrEntry(nil), entries...)
}

func (b *BpfObjects) recyclePDRImage(entries []IpEntrypointPdrEntry) {
	if cap(entries) > 0 && len(b.freePDRImages) < 2*MaxRulesPerSession {
		clear(entries[:cap(entries)])
		b.freePDRImages = append(b.freePDRImages, entries[:0])
	}
}

func (tx *ruleTransaction) pdrDraft(m *cilium.Map, key interface{}) (*pdrMutation, error) {
	k := pdrMutationKey{m, key}
	if tx.pdrs != nil {
		if draft := tx.pdrs[k]; draft != nil {
			return draft, nil
		}
	} else {
		for _, draft := range tx.pdrOrder {
			if draft.pdrMutationKey == k {
				return draft, nil
			}
		}
	}
	// These unpinned maps start empty and every control-plane writer uses this
	// journal. Configuration images avoid copying the large kernel bucket on
	// ordinary requests. Notification flags are packet-mutated, so snapshot those
	// buckets before constructing an undo image. Diagnostic readers copy the map.
	image, present := tx.objects.ruleImages[k]
	if present && image.hasNotification {
		var snapshot IpEntrypointPdrInfo
		if err := tx.objects.lookupPDR(m, key, &snapshot, false); err != nil {
			return nil, fmt.Errorf("snapshot PDR notification state: %w", err)
		}
		if snapshot.Count > MaxPDRsPerKey {
			return nil, fmt.Errorf("invalid PDR count %d", snapshot.Count)
		}
		image = publicationImage(snapshot.SessionId, append([]IpEntrypointPdrEntry(nil), snapshot.Entries[:snapshot.Count]...), image.slot)
	}
	draft := &pdrMutation{pdrMutationKey: k, owner: tx.sessionID, previous: image, previousSlot: image.slot, present: present}
	if present {
		if len(image.entries) > MaxPDRsPerKey {
			return nil, fmt.Errorf("invalid PDR count %d", len(image.entries))
		}
		if len(image.entries) != 0 && image.owner != tx.sessionID {
			return nil, ErrKeyOwned
		}
		draft.entries = tx.objects.copyPDRImage(image.entries)
	}

	// Most requests touch only one or two keys. Keep that lookup in the existing
	// order slice, then switch to a hash index before linear work can grow.
	if tx.pdrs == nil && len(tx.pdrOrder) == 8 {
		tx.pdrs = make(map[pdrMutationKey]*pdrMutation, len(tx.pdrOrder)+1)
		for _, previous := range tx.pdrOrder {
			tx.pdrs[previous.pdrMutationKey] = previous
		}
	}
	if tx.pdrs != nil {
		tx.pdrs[k] = draft
	}
	tx.pdrOrder = append(tx.pdrOrder, draft)
	return draft, nil
}
func (tx *ruleTransaction) stagePDR(m *cilium.Map, key interface{}, info PdrInfo) error {
	if info.SessionID != tx.sessionID {
		return ErrKeyOwned
	}
	entry, err := encodePDR(info)
	if err != nil {
		return err
	}
	draft, err := tx.pdrDraft(m, key)
	if err != nil {
		return err
	}
	for i := range draft.entries {
		if draft.entries[i].PdrId == info.PdrID {
			if draft.entries[i] == entry {
				return nil
			}
			draft.entries[i] = entry
			draft.changed = true
			return nil
		}
	}
	draft.entries = append(draft.entries, entry)
	draft.changed = true
	return nil
}
func (tx *ruleTransaction) stagePDRDelete(m *cilium.Map, key interface{}, owner uint64, id uint32) error {
	if owner != tx.sessionID {
		return ErrKeyOwned
	}
	draft, err := tx.pdrDraft(m, key)
	if err != nil {
		return err
	}
	for i := range draft.entries {
		if draft.entries[i].PdrId == id {
			draft.entries = append(draft.entries[:i], draft.entries[i+1:]...)
			draft.changed = true
			break
		}
	}
	return nil
}

// publishPDRs writes each complete final bucket once. Private slices may exceed
// the fixed map bound while PDRs move between keys; only final capacity counts.
// New keys precede removals. IPv4/TEID buckets live in stable array slots;
// IPv6 trie nodes have RCU-delayed frees (Linux v5.15 lpm_trie.c:381,
// v6.18 lpm_trie.c:451, kfree_rcu / bpf_mem_cache_free_rcu).
func (tx *ruleTransaction) publishPDRs() error {
	for _, draft := range tx.pdrOrder {
		if len(draft.entries) > MaxPDRsPerKey {
			return ErrRuleCapacity
		}
		if !draft.changed {
			tx.reusablePDRImages = append(tx.reusablePDRImages, draft.entries)
		}
	}
	for _, remove := range []bool{false, true} {
		for _, draft := range tx.pdrOrder {
			if !draft.changed || (len(draft.entries) == 0) != remove {
				continue
			}
			if len(draft.entries) > 1 {
				sort.Slice(draft.entries, func(i, j int) bool {
					a, b := draft.entries[i], draft.entries[j]
					if a.Precedence != b.Precedence {
						return a.Precedence < b.Precedence
					}
					return a.PdrId < b.PdrId
				})
			}
			// Put consumes its native value synchronously. Reuse one zeroed buffer
			// under ruleMutex; immutable images and undo records own separate slices.
			value := &tx.objects.publicationBucket.Info
			*value = IpEntrypointPdrInfo{SessionId: draft.owner, Count: uint32(len(draft.entries))}
			copy(value.Entries[:], draft.entries)
			// Configuration fields come from the publication image; mutable
			// notification flags were captured when the draft was created.
			if tx.beforeWrite != nil {
				if err := tx.beforeWrite(); err != nil {
					return err
				}
			}
			var err error
			var publishedSlot uint32
			if remove {
				err = draft.m.Delete(draft.key)
				if isKeyAbsent(err) {
					err = nil
				}
			} else {
				if draft.m == tx.objects.PdrMapDownlinkIp6 {
					err = draft.m.Put(draft.key, value)
				} else {
					var slot uint32
					slot, err = tx.allocateBucket()
					publishedSlot = slot
					if err == nil {
						key, kind := tx.objects.bucketKey(draft.m, draft.key)
						bucket := &tx.objects.publicationBucket
						bucket.Key, bucket.Kind = key, kind
						err = tx.objects.PdrBuckets.Put(slot, bucket)
						if err == nil && tx.beforeWrite != nil {
							err = tx.beforeWrite()
						}
						if err == nil {
							err = draft.m.Update(draft.key, &IpEntrypointPdrIndex{Slot: slot}, cilium.UpdateLock)
						}
					}
				}
			}
			if err != nil {
				return err
			}
			tx.dirty = true
			tx.graced = false
			original := draft
			tx.undo = append(tx.undo, func() error {
				var err error
				if original.present {
					if original.m == tx.objects.PdrMapDownlinkIp6 {
						previous := IpEntrypointPdrInfo{SessionId: original.previous.owner, Count: uint32(len(original.previous.entries))}
						copy(previous.Entries[:], original.previous.entries)
						err = original.m.Put(original.key, &previous)
					} else {
						err = original.m.Update(original.key, &IpEntrypointPdrIndex{Slot: original.previousSlot}, cilium.UpdateLock)
					}
				} else {
					err = original.m.Delete(original.key)
					if isKeyAbsent(err) {
						err = nil
					}
				}
				if err == nil {
					if original.present {
						tx.objects.ruleImages[original.pdrMutationKey] = original.previous
						tx.objects.recordPDRKey(original.m, original.key, original.previous.owner, len(original.previous.entries) > 0)
					} else {
						delete(tx.objects.ruleImages, original.pdrMutationKey)
						tx.objects.recordPDRKey(original.m, original.key, 0, false)
					}
				}
				return err
			})
			if remove {
				delete(tx.objects.ruleImages, draft.pdrMutationKey)
				tx.reusablePDRImages = append(tx.reusablePDRImages, draft.entries)
			} else {
				tx.objects.ruleImages[draft.pdrMutationKey] = publicationImage(draft.owner, draft.entries, publishedSlot)
			}
			// These Go images have no readers outside ruleMutex. Reuse only
			// after successful Commit makes every undo record unreachable.
			// Kernel bucket slots still follow their separate RCU grace.
			tx.reusablePDRImages = append(tx.reusablePDRImages, draft.previous.entries)
			tx.objects.recordPDRKey(draft.m, draft.key, value.SessionId, !remove)
			if remove {
				tx.retiredKey = true
			}
			if old := draft.previousSlot; old != 0 {
				tx.retired = append(tx.retired, func() error { tx.objects.releaseBucket(old); return nil })
			}
			draft.changed = false
		}
	}
	tx.pdrs = nil
	tx.pdrOrder = nil
	return nil
}
