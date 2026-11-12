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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cli/config"
)

func testCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCABundleReplacesSystemTrust(t *testing.T) {
	// crypto/x509 caches system roots once per process. Start this test alone
	// so SSL_CERT_FILE is set before any TLS verification loads that cache.
	if os.Getenv("EUPF_TEST_SYSTEM_ROOTS") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestCABundleReplacesSystemTrust$", "-test.v")
		cmd.Env = append(os.Environ(), "EUPF_TEST_SYSTEM_ROOTS=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated trust test: %v\n%s", err, out)
		}
		return
	}
	dir := t.TempDir()
	_, _, pinnedPEM := testCA(t, "configured CA")
	systemCA, systemKey, systemPEM := testCA(t, "system CA")
	bundle, system := filepath.Join(dir, "bundle.pem"), filepath.Join(dir, "system.pem")
	for path, data := range map[string][]byte{bundle: pinnedPEM, system: systemPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SSL_CERT_FILE", system)
	t.Setenv("SSL_CERT_DIR", filepath.Join(dir, "empty"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, systemCA, &key.PublicKey, systemKey)
	if err != nil {
		t.Fatal(err)
	}
	var tokens atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			tokens.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	defer srv.Close()
	control, err := NewEupfHttpRepository(srv.URL, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.GetUpfConfig(context.Background(), ""); err != nil {
		t.Fatalf("system-trusted control failed: %v", err)
	}
	pinned, err := NewEupfHttpRepository(srv.URL, &config.Config{ApiCABundle: bundle, ApiToken: "synthetic-token"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pinned.GetUpfConfig(context.Background(), "")
	var untrusted x509.UnknownAuthorityError
	if !errors.As(err, &untrusted) {
		t.Errorf("server outside configured bundle accepted: %v", err)
	}
	if tokens.Load() != 0 {
		t.Errorf("token reached server outside pinned trust: %d requests", tokens.Load())
	}
}
