package ebpf

import (
	"errors"
	"fmt"
	"sync"

	cilium "github.com/cilium/ebpf"
)

// ruleGrace batches reclamation behind a kernel RCU grace period. There is no
// map lookup, store or synchronization instruction in the packet program.
// Linux v5.15 kernel/bpf/syscall.c:maybe_wait_bpf_programs waits for every old
// BPF invocation after a map-in-map update; v7.3 uses the expedited variant.
// https://github.com/torvalds/linux/blob/v5.15/kernel/bpf/syscall.c#L148-L156
// https://github.com/torvalds/linux/blob/v7.3/kernel/bpf/syscall.c#L152-L164
// Native/generic XDP and BPF_PROG_TEST_RUN are non-sleepable RCU readers. Tail
// calls remain inside that reader; redirects consume no rule pointers after
// return. This also covers every local-tunnel tail call in the same invocation.
type ruleGrace struct {
	inner, outer *cilium.Map
	mu           sync.Mutex
	pending      []graceWork
	wake         chan struct{}
	stop         chan struct{}
	done         chan struct{}
	err          error
	synchronize  func() error
}

type graceWork struct {
	reclaim func() error
	done    chan error
	graced  bool
}

func newRuleGrace() (*ruleGrace, error) {
	spec := &cilium.MapSpec{Type: cilium.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
	inner, err := cilium.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("create rule grace inner map: %w", err)
	}
	outer, err := cilium.NewMap(&cilium.MapSpec{Type: cilium.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: spec})
	if err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("create rule grace outer map: %w", err)
	}
	g := &ruleGrace{inner: inner, outer: outer, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	g.synchronize = func() error { return g.outer.Put(uint32(0), g.inner) }
	go g.run()
	return g, nil
}

func (g *ruleGrace) enqueue(work graceWork) {
	g.mu.Lock()
	g.pending = append(g.pending, work)
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
}
func (g *ruleGrace) retire(reclaims []func() error, graced bool) {
	if len(reclaims) == 0 {
		return
	}
	g.mu.Lock()
	for _, reclaim := range reclaims {
		g.pending = append(g.pending, graceWork{reclaim: reclaim, graced: graced})
	}
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
}
func (g *ruleGrace) failure() error { g.mu.Lock(); defer g.mu.Unlock(); return g.err }
func (g *ruleGrace) wait() error {
	done := make(chan error, 1)
	g.enqueue(graceWork{done: done})
	return <-done
}
func (g *ruleGrace) drain() {
	g.mu.Lock()
	work := g.pending
	g.pending = nil
	g.mu.Unlock()
	if len(work) == 0 {
		return
	}
	// Even replacing an equal descriptor invokes maybe_wait_bpf_programs.
	var err error
	for _, item := range work {
		if !item.graced {
			err = g.synchronize()
			break
		}
	}
	if err == nil {
		for _, item := range work {
			if item.reclaim != nil {
				err = errors.Join(err, item.reclaim())
			}
		}
	}
	g.mu.Lock()
	g.err = errors.Join(g.err, err)
	err = g.err
	g.mu.Unlock()
	for _, item := range work {
		if item.done != nil {
			item.done <- err
		}
	}
}
func (g *ruleGrace) run() {
	defer close(g.done)
	for {
		select {
		case <-g.wake:
			g.drain()
		case <-g.stop:
			g.drain()
			return
		}
	}
}
func (g *ruleGrace) close() error {
	close(g.stop)
	<-g.done
	return errors.Join(g.failure(), g.outer.Close(), g.inner.Close())
}
