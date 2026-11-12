package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestTLSListenerAndCertificateValidation(t *testing.T) {
	reference := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer reference.Close()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	cert := reference.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewTLS("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.serve(l) }()
	defer func() { _ = s.Stop(context.Background()) }()
	roots := x509.NewCertPool()
	roots.AddCert(reference.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	legacy := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	connection, err := tls.Dial("tcp", l.Addr().String(), legacy)
	if err == nil {
		_ = connection.Close()
		t.Fatal("TLS 1.1 accepted")
	}
	if _, err := NewTLS("127.0.0.1:0", nil, certPath, "missing.key"); err == nil {
		t.Fatal("invalid key accepted")
	}
}
