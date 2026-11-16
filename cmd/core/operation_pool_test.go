package core

import (
	"errors"
	"fmt"
	"github.com/gomaja-labs/go-pfcp/ie"
	"reflect"
	"testing"
)

func TestOperationPoolReservesBeforeAnyWrite(t *testing.T) {
	var order []string
	p := NewOperationPool()
	p.Before = func() error { order = append(order, "begin"); return nil }
	for _, id := range []string{"1", "2"} {
		p.Add(Operation{Reserve: func() error { order = append(order, "reserve"+id); return nil }, Detach: func() error { order = append(order, "detach"+id); return nil }, Apply: func() error { order = append(order, "write"+id); return nil }})
	}
	if err := p.Commit(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"begin", "reserve1", "reserve2", "write1", "write2", "detach1", "detach2"}) {
		t.Fatal(order)
	}
}
func TestOperationPoolFailedReservationWritesNothing(t *testing.T) {
	writes := 0
	p := NewOperationPool()
	p.Add(Operation{Apply: func() error { writes++; return nil }})
	p.Add(Operation{Reserve: func() error { return errors.New("full") }, Apply: func() error { writes++; return nil }})
	if p.Commit() == nil || writes != 0 {
		t.Fatalf("writes=%d", writes)
	}
}

func TestOperationPoolIdentifiesRuleFailureInEveryPhase(t *testing.T) {
	for _, kind := range []uint8{ie.RuleIDTypePDR, ie.RuleIDTypeFAR, ie.RuleIDTypeQER, ie.RuleIDTypeURR} {
		for _, phase := range []string{"reserve", "apply", "detach", "retire"} {
			t.Run(fmt.Sprintf("%d/%s", kind, phase), func(t *testing.T) {
				fault := errors.New("operation failed")
				failed := func() error { return fault }
				operation := Operation{}
				switch phase {
				case "reserve":
					operation.Reserve = failed
				case "apply":
					operation.Apply = failed
				case "detach":
					operation.Detach = failed
				case "retire":
					operation.Retire = failed
				}
				pool := NewOperationPool()
				pool.AddRule(kind, 7, operation)
				err := pool.Commit()
				var rule *ruleFailure
				if !errors.Is(err, fault) || !errors.As(err, &rule) || rule.kind != kind || rule.id != 7 {
					t.Fatalf("lost rule failure metadata: %v", err)
				}
			})
		}
	}
}
