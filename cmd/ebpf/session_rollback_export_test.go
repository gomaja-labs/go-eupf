//go:build linux

package ebpf

import (
	"errors"
	"sync"
	"testing"
)

// TransientUndoPlane exercises the real journal and grace worker; only its
// first publication and first undo attempt fail. It exists only in tests.
type TransientUndoPlane struct {
	*BpfObjects
	Faulted, Repaired chan struct{}
	injected          bool
}

// NewTransientUndoPlane creates an isolated kernel-backed transaction fixture.
func NewTransientUndoPlane(t *testing.T) *TransientUndoPlane {
	return &TransientUndoPlane{BpfObjects: loadBufferContinuationDatapath(t), Faulted: make(chan struct{}), Repaired: make(chan struct{})}
}

// BeginRuleTransaction injects failure after the first real PDR publication.
func (plane *TransientUndoPlane) BeginRuleTransaction(id uint64) (RuleTransaction, error) {
	transaction, err := plane.BpfObjects.BeginRuleTransaction(id)
	if err != nil || plane.injected {
		return transaction, err
	}
	tx := transaction.(*ruleTransaction)
	tx.beforeWrite = func() error {
		published := false
		for _, draft := range tx.pdrOrder {
			if draft.m == plane.PdrMapDownlinkIp6 {
				continue
			}
			var index IpEntrypointPdrIndex
			if err := draft.m.Lookup(draft.key, &index); err == nil && index.Slot != 0 {
				var bucket IpEntrypointPdrBucket
				if err := plane.PdrBuckets.Lookup(index.Slot, &bucket); err == nil && bucket.Info.SessionId == id {
					published = true
				}
			}
		}
		if !published || len(tx.undo) == 0 {
			return nil
		}
		plane.injected = true
		original := tx.undo[len(tx.undo)-1]
		first := true
		var repaired sync.Once
		tx.undo[len(tx.undo)-1] = func() error {
			if first {
				first = false
				close(plane.Faulted)
				return errors.New("synthetic transient undo failure")
			}
			err := original()
			if err == nil {
				repaired.Do(func() { close(plane.Repaired) })
			}
			return err
		}
		return errors.New("synthetic publication failure")
	}
	return tx, nil
}
