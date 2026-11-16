package core

import (
	"errors"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestRuleViewsAreScopedToOneRequest(t *testing.T) {
	value := ie.NewPDI(ie.NewSourceInterface(0))
	first := NewPDRCreationContext(nil, nil)
	one, err := cachedRuleView(&first.views, value, (*ie.IE).PDI)
	if err != nil {
		t.Fatal(err)
	}
	again, err := cachedRuleView(&first.views, value, (*ie.IE).PDI)
	if err != nil || again != one {
		t.Fatal("request decoded the same view twice", err)
	}
	value.ChildIEs = []*ie.IE{ie.NewSourceInterface(1)}
	next := NewPDRCreationContext(nil, nil)
	two, err := cachedRuleView(&next.views, value, (*ie.IE).PDI)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := one.SourceInterface.SourceInterface()
	b, _ := two.SourceInterface.SourceInterface()
	if a != 0 || b != 1 {
		t.Fatal("a later request inherited an earlier syntax view", a, b)
	}
}

func TestRuleViewsDoNotCacheFailedDecoding(t *testing.T) {
	var views ruleViews
	value := ie.NewPDI(ie.NewSourceInterface(0))
	failure := errors.New("synthetic decode failure")
	calls := 0
	decode := func(i *ie.IE) (*ie.PDIFields, error) {
		calls++
		if calls == 1 {
			return nil, failure
		}
		return i.PDI()
	}
	if _, err := cachedRuleView(&views, value, decode); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := cachedRuleView(&views, value, decode); err != nil || calls != 2 {
		t.Fatal("failure poisoned a later decode", calls, err)
	}
}
