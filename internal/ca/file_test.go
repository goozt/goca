package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goozt/gopgbase/infra/ca/internal/ca"
)

// generateSelfSignedCert creates a minimal self-signed cert and key pair,
// writes them to dir, and returns the paths.
func generateSelfSignedCert(t *testing.T, dir string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	certPath = filepath.Join(dir, "test.crt")
	keyPath = filepath.Join(dir, "test.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestLoadCAFromFiles_ValidCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir, time.Now().Add(time.Hour))

	cert, key, err := ca.LoadCAFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("expected non-nil cert and key")
	}
}

func TestLoadCAFromFiles_ExpiredCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir, time.Now().Add(-time.Hour))

	_, _, err := ca.LoadCAFromFiles(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for expired cert, got nil")
	}
}

func TestLoadCAFromFiles_KeyMismatch(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := generateSelfSignedCert(t, dir, time.Now().Add(time.Hour))

	// Generate a different key and write it as the key file.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(otherKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	mismatchKeyPath := filepath.Join(dir, "mismatch.key")
	os.WriteFile(mismatchKeyPath, keyPEM, 0600)

	_, _, err = ca.LoadCAFromFiles(certPath, mismatchKeyPath)
	if err == nil {
		t.Fatal("expected error for key mismatch, got nil")
	}
}

func TestLoadCAFromFiles_MissingFile(t *testing.T) {
	_, _, err := ca.LoadCAFromFiles("/nonexistent/cert.crt", "/nonexistent/key.key")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
