package config

// MaxRulesPerSession bounds each rule family admitted by one PFCP transaction.
// A serialized journal reserves one batch for publication and one for retirement.
const MaxRulesPerSession = 64

func versionedRuleCapacity(live int64) int64 {
	return live + min(live, int64(2*MaxRulesPerSession))
}
