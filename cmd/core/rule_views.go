package core

import "github.com/gomaja-labs/go-pfcp/ie"

// ruleViews belongs to one request's PDR creation context. Capability checks,
// network-instance checks and planning share immutable codec views. Neither
// the input syntax nor a cached view may be changed during that request.
type ruleViews map[*ie.IE]any

func cachedRuleView[T any](views *ruleViews, value *ie.IE, decode func(*ie.IE) (*T, error)) (*T, error) {
	if views != nil {
		if cached, ok := (*views)[value].(*T); ok {
			return cached, nil
		}
	}
	result, err := decode(value)
	if err == nil && views != nil {
		if *views == nil {
			*views = make(ruleViews)
		}
		(*views)[value] = result
	}
	return result, err
}
