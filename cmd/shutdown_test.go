package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	kernel "github.com/cilium/ebpf"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestSuperviseWaitsForDeferredCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cleaned := false
	run := func(ctx context.Context) error { defer func() { cleaned = true }(); <-ctx.Done(); return nil }
	cancel()
	if err := supervise(ctx, run, time.Second); err != nil {
		t.Fatal(err)
	}
	if !cleaned {
		t.Fatal("returned before cleanup")
	}
}
func TestSuperviseBoundsHungShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unblock := make(chan struct{})
	err := supervise(ctx, func(context.Context) error { <-unblock; return nil }, 10*time.Millisecond)
	close(unblock)
	if err == nil || !strings.Contains(err.Error(), "shutdown deadline") {
		t.Fatalf("error=%v", err)
	}
}
func TestSupervisePreservesStartupFailure(t *testing.T) {
	failure := errors.New("startup failed")
	if err := supervise(context.Background(), func(context.Context) error { return failure }, time.Second); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}
func TestSDFListenerInitializationReturnsFailure(t *testing.T) {
	m, err := kernel.NewMap(&kernel.MapSpec{Type: kernel.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := newStartupSdfListener(m)
	if err == nil || listener != nil {
		t.Fatalf("listener=%v error=%v", listener, err)
	}
}

func TestAssociationReleaseWaitUsesLockedSnapshots(t *testing.T) {
	resources, err := service.NewResourceManager("", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, resources, nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			request := message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("synthetic.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))
			wire := make([]byte, request.MarshalLen())
			if err := request.MarshalTo(wire); err != nil {
				t.Error(err)
				return
			}
			conn.Handle(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 8805})
			conn.DeleteAllAssociations()
		}
	}()
	waitForAllAssocReleases(ctx, conn)
	cancel()
	<-done
}
