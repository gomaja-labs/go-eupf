package core

import (
	"errors"
	"reflect"
	"testing"
)

func TestOperationPoolReservesBeforeAnyWrite(t *testing.T) {
	var order []string
	p := NewOperationPool()
	p.Before = func() error { order = append(order, "begin"); return nil }
	for _, id := range []string{"1", "2"} {
		p.Add(Operation{Reserve: func() error { order = append(order, "reserve"+id); return nil }, Apply: func() error { order = append(order, "write"+id); return nil }})
	}
	if err := p.Commit(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"begin", "reserve1", "reserve2", "write1", "write2"}) {
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
