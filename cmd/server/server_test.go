package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestShutdownReturnsSuccess(t *testing.T) {
	s := New("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.serve(listener) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("normal shutdown error: %v", err)
	}
}
func TestShutdownDeadlineClosesActiveRequests(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s := New("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release }))
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.serve(listener) }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("active request remained connected after shutdown deadline")
	}
	close(release)
}
