//go:build linux

package ebpf

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBufferBackgroundPreparationDoesNotHoldClose(t *testing.T) {
	b := loadBufferContinuationDatapath(t)
	done := b.StartBufferPrograms(context.Background())
	started := time.Now()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if delay := time.Since(started); delay > time.Second {
		t.Fatalf("Close waited for verifier: %s", delay)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("private loader did not finish")
	}
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	if b.admissionCollection != nil || b.renderCollection != nil {
		t.Fatal("background load installed after close")
	}
	if b.prepareError == nil || strings.Contains(b.prepareError.Error(), "bad file descriptor") {
		t.Fatalf("private loader lost its input descriptors: %v", b.prepareError)
	}
}

func TestBufferCanceledPreparationDoesNotInstall(t *testing.T) {
	b := loadBufferContinuationDatapath(t)
	before := b.UpfIpEntrypointFunc
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	<-b.StartBufferPrograms(ctx)
	if b.UpfIpEntrypointFunc != before || b.admissionCollection != nil || b.renderCollection != nil {
		t.Fatal("canceled load changed live forwarding")
	}
	if _, err := b.BufferKernelIngressProgram(); err == nil {
		t.Fatal("canceled preparation returned output")
	}
	// Starting again must return the same terminal result, without a retry.
	<-b.StartBufferPrograms(context.Background())
	if b.UpfIpEntrypointFunc != before {
		t.Fatal("failed load retried")
	}
}
