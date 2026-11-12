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
	owner   uint64
	entries []IpEntrypointPdrEntry
	changed bool
}

func (tx *ruleTransaction) pdrDraft(m *cilium.Map, key interface{}) (*pdrMutation, error) {
	k := pdrMutationKey{m, key}
	if draft := tx.pdrs[k]; draft != nil {
		return draft, nil
	}
	var bucket IpEntrypointPdrInfo
	if err := lookupRuleValue(m, key, &bucket); err != nil && !isKeyAbsent(err) {
		return nil, err
	}
	if bucket.Count > MaxPDRsPerKey {
		return nil, fmt.Errorf("invalid PDR count %d", bucket.Count)
	}
	if bucket.Count != 0 && bucket.SessionId != tx.sessionID {
		return nil, ErrKeyOwned
	}
	draft := &pdrMutation{pdrMutationKey: k, owner: tx.sessionID, entries: append([]IpEntrypointPdrEntry(nil), bucket.Entries[:bucket.Count]...)}
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
			if err := journalRule[IpEntrypointPdrInfo](tx, draft.m, draft.key, func() error {
				if remove {
					err := draft.m.Delete(draft.key)
					if isKeyAbsent(err) {
						return nil
					}
					return err
				}
				return draft.m.Put(draft.key, &value)
			}); err != nil {
				return err
			}
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
