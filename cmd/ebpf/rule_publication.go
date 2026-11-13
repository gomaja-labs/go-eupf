package ebpf

import (
	"fmt"
	"sort"

	cilium "github.com/cilium/ebpf"
)

type pdrImage struct {
	value           *IpEntrypointPdrInfo
	slot            uint32
	hasNotification bool
}

func publicationImage(value *IpEntrypointPdrInfo, slot uint32) pdrImage {
	image := pdrImage{value: value, slot: slot}
	for _, entry := range value.Entries[:value.Count] {
		image.hasNotification = image.hasNotification || entry.Notify != 0
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
	previous     *IpEntrypointPdrInfo
	present      bool
	previousSlot uint32
}

func (tx *ruleTransaction) pdrDraft(m *cilium.Map, key interface{}) (*pdrMutation, error) {
	k := pdrMutationKey{m, key}
	if draft := tx.pdrs[k]; draft != nil {
		return draft, nil
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
		image.value = &snapshot
	}
	draft := &pdrMutation{pdrMutationKey: k, owner: tx.sessionID, previous: image.value, previousSlot: image.slot, present: present}
	if present {
		bucket := image.value
		if bucket.Count > MaxPDRsPerKey {
			return nil, fmt.Errorf("invalid PDR count %d", bucket.Count)
		}
		if bucket.Count != 0 && bucket.SessionId != tx.sessionID {
			return nil, ErrKeyOwned
		}
		draft.entries = append([]IpEntrypointPdrEntry(nil), bucket.Entries[:bucket.Count]...)
	}

	if tx.pdrs == nil {
		tx.pdrs = make(map[pdrMutationKey]*pdrMutation)
	}
	tx.pdrs[k] = draft
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
	}
	for _, remove := range []bool{false, true} {
		for _, draft := range tx.pdrOrder {
			if !draft.changed || (len(draft.entries) == 0) != remove {
				continue
			}
			sort.Slice(draft.entries, func(i, j int) bool {
				a, b := draft.entries[i], draft.entries[j]
				if a.Precedence != b.Precedence {
					return a.Precedence < b.Precedence
				}
				return a.PdrId < b.PdrId
			})
			var value IpEntrypointPdrInfo
			value.SessionId, value.Count = draft.owner, uint32(len(draft.entries))
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
					err = draft.m.Put(draft.key, &value)
				} else {
					var slot uint32
					slot, err = tx.allocateBucket()
					publishedSlot = slot
					if err == nil {
						key, kind := tx.objects.bucketKey(draft.m, draft.key)
						bucket := IpEntrypointPdrBucket{Key: key, Kind: kind, Info: value}
						err = tx.objects.PdrBuckets.Put(slot, &bucket)
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
						err = original.m.Put(original.key, original.previous)
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
						tx.objects.ruleImages[original.pdrMutationKey] = publicationImage(original.previous, original.previousSlot)
						tx.objects.recordPDRKey(original.m, original.key, original.previous.SessionId, original.previous.Count > 0)
					} else {
						delete(tx.objects.ruleImages, original.pdrMutationKey)
						tx.objects.recordPDRKey(original.m, original.key, 0, false)
					}
				}
				return err
			})
			if remove {
				delete(tx.objects.ruleImages, draft.pdrMutationKey)
			} else {
				tx.objects.ruleImages[draft.pdrMutationKey] = publicationImage(&value, publishedSlot)
			}
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
