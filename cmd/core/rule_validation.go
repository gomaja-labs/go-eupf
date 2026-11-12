package core

import (
	"fmt"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"github.com/gomaja-labs/go-pfcp/ie"
)

type ruleKey struct {
	kind uint8
	id   uint32
}

type ruleChange struct {
	key      ruleKey
	create   bool
	remove   bool
	children []*ie.IE
}

func readRuleChange(value *ie.IE) (ruleChange, error) {
	change := ruleChange{}
	var idType ie.IEType
	switch value.Type {
	case ie.CreatePDR, ie.UpdatePDR, ie.RemovePDR:
		change.key.kind, idType = ie.RuleIDTypePDR, ie.PDRID
		change.create, change.remove = value.Type == ie.CreatePDR, value.Type == ie.RemovePDR
	case ie.CreateFAR, ie.UpdateFAR, ie.RemoveFAR:
		change.key.kind, idType = ie.RuleIDTypeFAR, ie.FARID
		change.create, change.remove = value.Type == ie.CreateFAR, value.Type == ie.RemoveFAR
	case ie.CreateQER, ie.UpdateQER, ie.RemoveQER:
		change.key.kind, idType = ie.RuleIDTypeQER, ie.QERID
		change.create, change.remove = value.Type == ie.CreateQER, value.Type == ie.RemoveQER
	case ie.CreateURR, ie.UpdateURR, ie.RemoveURR:
		change.key.kind, idType = ie.RuleIDTypeURR, ie.URRID
		change.create, change.remove = value.Type == ie.CreateURR, value.Type == ie.RemoveURR
	default:
		return change, fmt.Errorf("unsupported rule IE %d", value.Type)
	}
	children, err := value.ValueAsGrouped()
	if err != nil {
		return change, err
	}
	change.children = children
	for _, child := range children {
		if child.Type != idType {
			continue
		}
		if idType == ie.PDRID {
			id, err := child.PDRID()
			change.key.id = uint32(id)
			return change, err
		}
		change.key.id, err = child.ValueAsUint32()
		return change, err
	}
	return change, fmt.Errorf("missing rule ID IE %d: %w", idType, ie.ErrIENotFound)
}

// validateSessionRuleIDs is a read-only preflight. Rule IDs are scoped to a
// session and a rule type, never to global map slots. TS 29.244 V20.1.0 clauses
// 5.2.1 and 6.3.3.2-6.3.3.3 prohibit duplicates and updates of unknown rules.
func validateSessionRuleIDs(session *Session, lists ...[]*ie.IE) error {
	known := make(map[ruleKey]bool)
	for id := range session.PDRs {
		known[ruleKey{ie.RuleIDTypePDR, id}] = true
	}
	for id := range session.FARs {
		known[ruleKey{ie.RuleIDTypeFAR, id}] = true
	}
	for id := range session.QERs {
		known[ruleKey{ie.RuleIDTypeQER, id}] = true
	}
	for id := range session.URRs {
		known[ruleKey{ie.RuleIDTypeURR, id}] = true
	}
	seen := make(map[ruleKey]bool)
	var changes []ruleChange
	for _, list := range lists {
		for _, value := range list {
			change, err := readRuleChange(value)
			if err != nil {
				return &ruleFailure{change.key.kind, change.key.id, err}
			}
			if err := validateRuleCapability(value); err != nil {
				return &ruleFailure{change.key.kind, change.key.id, err}
			}
			key := change.key
			if seen[key] {
				return &ruleFailure{key.kind, key.id, fmt.Errorf("multiple operations for one rule")}
			}
			seen[key] = true
			if change.create == known[key] {
				return &ruleFailure{key.kind, key.id, fmt.Errorf("create=%t, rule exists=%t", change.create, known[key])}
			}
			known[key] = !change.remove
			count := 0
			for rule, present := range known {
				if rule.kind == key.kind && present {
					count++
				}
			}
			if count > 64 {
				return &ruleFailure{key.kind, key.id, ebpf.ErrRuleCapacity}
			}
			changes = append(changes, change)
		}
	}
	for _, change := range changes {
		if change.key.kind != ie.RuleIDTypePDR || change.remove {
			continue
		}
		cleared := make(map[ie.IEType]bool)
		if !change.create {
			for _, child := range change.children {
				if (child.Type == ie.QERID || child.Type == ie.URRID) && isNullIE(child) {
					cleared[child.Type] = true
				}
			}
		}
		farSeen := false
		for _, child := range change.children {
			if cleared[child.Type] {
				continue
			}
			var kind uint8
			switch child.Type {
			case ie.FARID:
				// TS 29.244 V20.1.0 clause 7.6.10: singular fields
				// use the first occurrence, including in the preflight.
				if farSeen {
					continue
				}
				farSeen = true
				kind = ie.RuleIDTypeFAR
			case ie.QERID:
				kind = ie.RuleIDTypeQER
			case ie.URRID:
				kind = ie.RuleIDTypeURR
			default:
				continue
			}
			// A null list occurrence removes all bindings of the type (5.6.3).
			if !change.create && isNullIE(child) {
				continue
			}
			id, err := child.ValueAsUint32()
			if err != nil {
				return &ruleFailure{change.key.kind, change.key.id, err}
			}
			if !known[ruleKey{kind, id}] {
				return &ruleFailure{change.key.kind, change.key.id, fmt.Errorf("unknown referenced rule type %d ID %d", kind, id)}
			}
		}
	}
	return nil
}
