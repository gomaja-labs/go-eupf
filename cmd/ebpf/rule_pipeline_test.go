//go:build linux

package ebpf

import (
	"fmt"
	"testing"
	"time"
)

func TestRuleCommitDoesNotWaitForReclamation(t *testing.T) {
	b := loadDatapath(t)
	original := b.grace.synchronize
	entered := make(chan struct{}, 1)
	resume := make(chan struct{})
	b.grace.synchronize = func() error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-resume
		return original()
	}
	tx, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- tx.Commit() }()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("rule publication waited for reclamation")
		close(resume)
		if err := <-done; err != nil {
			t.Error(err)
		}
		return
	}
	close(resume)
}

func TestFailedRuleAllocationRemainsQuarantinedUntilRollbackGrace(t *testing.T) {
	b := loadDatapath(t)
	if _, err := b.GetNextFAR(); err != nil {
		t.Fatal(err)
	}
	original := b.grace.synchronize
	resume := make(chan struct{})
	b.grace.synchronize = func() error { <-resume; return original() }
	defer close(resume)
	controller, err := b.BeginRuleTransaction(0)
	if err != nil {
		t.Fatal(err)
	}
	tx := controller.(*ruleTransaction)
	tx.beforeWrite = func() error { return fmt.Errorf("synthetic map write failure") }
	if _, err := tx.NewFar(FarInfo{Action: 1}); err == nil {
		t.Fatal("injected write succeeded")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	later, err := b.BeginRuleTransaction(9)
	if err != nil {
		t.Fatal(err)
	}
	id, err := later.NewFar(FarInfo{Action: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := later.Commit(); err != nil {
		t.Fatal(err)
	}
	if id == 2 {
		t.Fatal("failed allocation reused before its pending rollback release")
	}
}
