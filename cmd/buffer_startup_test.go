package main

import (
	"context"
	"testing"
	"time"
)

func TestBufferingStartsFromListenerSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, started, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		startBufferingAfterAPI(ctx, ready, func(context.Context) <-chan struct{} { close(started); return nil })
	}()
	select {
	case <-started:
		t.Fatal("preparation started before listener readiness")
	case <-time.After(20 * time.Millisecond):
	}
	close(ready)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("listener readiness did not start preparation")
	}
	<-done
}

func TestBufferingListenerWaitStopsOnShutdown(t *testing.T) {
	for _, readyClosed := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ready := make(chan struct{})
		if readyClosed {
			close(ready)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			startBufferingAfterAPI(ctx, ready, func(context.Context) <-chan struct{} { t.Error("started during shutdown"); return nil })
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("listener readiness wait ignored shutdown")
		}
	}
}
