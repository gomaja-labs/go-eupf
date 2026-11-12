package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cli/config"
)

func TestRepositoryVerifiesTLSWithCustomCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	repo, initErr := NewEupfHttpRepository(srv.URL, &config.Config{ApiCABundle: path})
	if initErr != nil {
		t.Fatal(initErr)
	}
	if _, err := repo.GetUpfConfig(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryRejectsUntrustedTLSAndInvalidCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	repo, err := NewEupfHttpRepository(srv.URL, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetUpfConfig(context.Background(), ""); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	path := filepath.Join(t.TempDir(), "not-ca.pem")
	if err := os.WriteFile(path, []byte("not a CA"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + ".missing"} {
		if _, err := NewEupfHttpRepository(srv.URL, &config.Config{ApiCABundle: file}); err == nil {
			t.Fatalf("accepted invalid CA bundle %q", file)
		}
	}
}

// RFC 9110 section 4.3.4 and verified Errata 7105 prohibit CN-ID fallback.
// RFC 9525 sections 4.1 and 6.4 require a matching SAN for the IP reference.
func TestRepositoryRequiresSANIdentity(t *testing.T) {
	for _, dns := range []string{"", "other.example"} {
		t.Run(dns, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if dns != "" {
				cert.DNSNames = []string{dns}
			}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			server.StartTLS()
			defer server.Close()
			file := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			repo, err := NewEupfHttpRepository(server.URL, &config.Config{ApiCABundle: file})
			if err != nil {
				t.Fatal(err)
			}
			_, err = repo.GetUpfConfig(context.Background(), "")
			var identity x509.HostnameError
			if !errors.As(err, &identity) {
				t.Fatalf("matching CN or mismatched SAN accepted; error=%v", err)
			}
		})
	}
}
