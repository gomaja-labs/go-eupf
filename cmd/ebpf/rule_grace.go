package ebpf

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

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
	inner, outer  *cilium.Map
	mu            sync.Mutex
	pending       []graceWork
	wake          chan struct{}
	stop          chan struct{}
	done          chan struct{}
	err           error
	failures      chan error
	synchronize   func() error
	capacityReady chan struct{}
}

type graceWork struct {
	reclaim   func() error
	done      chan error
	graced    bool
	prepare   func() error
	sessionID uint64
	failedAt  time.Time
	delay     time.Duration
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
	g := &ruleGrace{failures: make(chan error, 1), inner: inner, outer: outer, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
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

// ruleCapacityWait is one transaction's total wait budget after its first slot
// shortage, excluding execution/scheduling time. Exhaustion remains temporary
// resource unavailability (TS 29.244 V20.1.0 table 8.2.1-1, Cause 75).
const ruleCapacityWait = 100 * time.Millisecond

func (g *ruleGrace) waitForCapacity(deadline time.Time) error {
	delay := time.Until(deadline)
	if delay <= 0 {
		return ErrRuleCapacity
	}
	g.mu.Lock()
	if g.err != nil {
		err := g.err
		g.mu.Unlock()
		return err
	}
	ready := g.capacityReady
	if ready == nil {
		ready = make(chan struct{})
		g.capacityReady = ready
		g.pending = append(g.pending, graceWork{reclaim: func() error {
			g.mu.Lock()
			g.capacityReady = nil
			close(ready)
			g.mu.Unlock()
			return nil
		}})
	}
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
	// One shared completion bounds retained waiter state even if the kernel
	// barrier stalls indefinitely and successive requests exhaust their budget.
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ready:
		return g.failure()
	case <-timer.C:
		if err := g.failure(); err != nil {
			return err
		}
		return fmt.Errorf("rule retirement wait exceeded: %w", ErrRuleCapacity)
	}
}

// ruleRecoveryWindow bounds actual I/O failures, never successful progress.
// Keep all affected identifiers reserved; after retries, the process supervisor
// must restart the UPF with fresh maps. Backoff is 100, 200, 400, then 500 ms.
const ruleRecoveryWindow = 3 * time.Second

func (g *ruleGrace) drain() {
	g.mu.Lock()
	work := g.pending
	g.pending = nil
	g.mu.Unlock()
	for len(work) > 0 {
		var ready, retry []graceWork
		for _, item := range work {
			if item.prepare != nil {
				if err := item.prepare(); err != nil {
					g.retryWork(item, err, &retry)
					continue
				}
				item.prepare = nil
			}
			ready = append(ready, item)
		}
		var graceErr error
		for _, item := range ready {
			if !item.graced {
				graceErr = g.synchronize()
				break
			}
		}
		for _, item := range ready {
			if graceErr != nil {
				g.retryWork(item, graceErr, &retry)
				continue
			}
			item.graced = true
			if item.reclaim != nil {
				if err := item.reclaim(); err != nil {
					g.retryWork(item, err, &retry)
					continue
				}
			}
			if item.done != nil {
				item.done <- nil
			}
		}
		if len(retry) == 0 {
			return
		}
		delay := time.Duration(0)
		for _, item := range retry {
			delay = max(delay, item.delay)
		}
		time.Sleep(delay)
		g.mu.Lock()
		work = append(retry, g.pending...)
		g.pending = nil
		g.mu.Unlock()
	}
}
func (g *ruleGrace) retryWork(item graceWork, err error, retry *[]graceWork) {
	now := time.Now()
	if item.failedAt.IsZero() {
		item.failedAt = now
	}
	log.Error().Err(err).Uint64("session", item.sessionID).Dur("retry_for", now.Sub(item.failedAt)).Msg("Rule reclamation failed; keep identifiers reserved")
	if now.Sub(item.failedAt) >= ruleRecoveryWindow {
		fatal := fmt.Errorf("session %d rule recovery failed for %s: %w", item.sessionID, ruleRecoveryWindow, err)
		g.mu.Lock()
		g.err = errors.Join(g.err, fatal)
		g.mu.Unlock()
		if g.failures != nil {
			select {
			case g.failures <- fatal:
			default:
			}
		}
		if item.done != nil {
			item.done <- fatal
		}
		return
	}
	if item.delay == 0 {
		item.delay = 100 * time.Millisecond
	} else {
		item.delay = min(500*time.Millisecond, item.delay*2)
	}
	*retry = append(*retry, item)
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

// AfterRuleGrace runs work after all XDP invocations preceding this call have
// completed. The work must not acquire a control-plane lock or block on I/O.
func (b *BpfObjects) AfterRuleGrace(work func() error) error {
	b.ruleMutex.Lock()
	defer b.ruleMutex.Unlock()
	if b.ruleClosed || b.grace == nil {
		return errors.New("rule grace is unavailable")
	}
	if err := b.grace.failure(); err != nil {
		return err
	}
	b.grace.enqueue(graceWork{reclaim: work})
	return nil
}
