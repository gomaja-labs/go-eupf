package ebpf

import (
	"fmt"
	"sort"

	cilium "github.com/cilium/ebpf"
)

type pdrMutationKey struct {
	m   *cilium.Map
	key interface{}
}
type pdrMutation struct {
	pdrMutationKey
	owner    uint64
	entries  []IpEntrypointPdrEntry
	changed  bool
	previous *IpEntrypointPdrInfo
	present  bool
}

func (tx *ruleTransaction) pdrDraft(m *cilium.Map, key interface{}) (*pdrMutation, error) {
	k := pdrMutationKey{m, key}
	if draft := tx.pdrs[k]; draft != nil {
		return draft, nil
	}
	var bucket IpEntrypointPdrInfo
	lookupErr := lookupRuleValue(m, key, &bucket)
	if lookupErr != nil && !isKeyAbsent(lookupErr) {
		return nil, lookupErr
	}
	if bucket.Count > MaxPDRsPerKey {
		return nil, fmt.Errorf("invalid PDR count %d", bucket.Count)
	}
	if bucket.Count != 0 && bucket.SessionId != tx.sessionID {
		return nil, ErrKeyOwned
	}
	draft := &pdrMutation{previous: &bucket, present: lookupErr == nil, pdrMutationKey: k, owner: tx.sessionID, entries: append([]IpEntrypointPdrEntry(nil), bucket.Entries[:bucket.Count]...)}
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
// New keys precede removal of old keys. Hash values use NO_PREALLOC so that old
// values remain intact until RCU reclamation (Linux v5.15 hashtab.c:free_htab_elem).
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
			// PDR values are immutable to packet readers. The transaction's
			// original key lookup is the exact undo image under ruleMutex;
			// rereading the large bucket twice adds no information.
			if tx.beforeWrite != nil {
				if err := tx.beforeWrite(); err != nil {
					return err
				}
			}
			var err error
			if remove {
				err = draft.m.Delete(draft.key)
				if isKeyAbsent(err) {
					err = nil
				}
			} else {
				err = draft.m.Put(draft.key, &value)
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
					err = original.m.Put(original.key, original.previous)
				} else {
					err = original.m.Delete(original.key)
					if isKeyAbsent(err) {
						err = nil
					}
				}
				if err == nil {
					tx.objects.recordPDRKey(original.m, original.key, original.previous.SessionId, original.present && original.previous.Count > 0)
				}
				return err
			})
			tx.objects.recordPDRKey(draft.m, draft.key, value.SessionId, !remove)
			if remove {
				tx.retiredKey = true
			}
			draft.changed = false
		}
	}
	tx.pdrs = nil
	tx.pdrOrder = nil
	return nil
}
