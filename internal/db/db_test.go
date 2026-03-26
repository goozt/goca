package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return d
}

func makeCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestOpen_EmptyDB(t *testing.T) {
	d := newTestDB(t)
	if len(d.s.Issued) != 0 {
		t.Errorf("expected empty Issued map, got %d entries", len(d.s.Issued))
	}
	if len(d.s.Revoked) != 0 {
		t.Errorf("expected empty Revoked map, got %d entries", len(d.s.Revoked))
	}
}

func TestSaveIssuedCert_RoundTrip(t *testing.T) {
	d := newTestDB(t)
	cert := makeCert(t, 42)

	if err := d.SaveIssuedCert(cert, "node1"); err != nil {
		t.Fatalf("SaveIssuedCert: %v", err)
	}

	ic, ok := d.GetIssuedByHostname("node1")
	if !ok {
		t.Fatal("expected to find issued cert, got nothing")
	}
	if ic.Hostname != "node1" {
		t.Errorf("hostname: got %q, want %q", ic.Hostname, "node1")
	}
	if ic.SerialHex != cert.SerialNumber.Text(16) {
		t.Errorf("serial: got %q, want %q", ic.SerialHex, cert.SerialNumber.Text(16))
	}
}

func TestGetIssuedByHostname_Missing(t *testing.T) {
	d := newTestDB(t)
	_, ok := d.GetIssuedByHostname("nobody")
	if ok {
		t.Error("expected ok=false for unknown hostname")
	}
}

func TestAddRevocation_ListRevocations(t *testing.T) {
	d := newTestDB(t)
	cert := makeCert(t, 99)
	serialHex := cert.SerialNumber.Text(16)

	if err := d.AddRevocation(serialHex, time.Now().UTC(), 0); err != nil {
		t.Fatalf("AddRevocation: %v", err)
	}

	revs := d.ListRevocations()
	if len(revs) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(revs))
	}
	if revs[0].SerialHex != serialHex {
		t.Errorf("serial: got %q, want %q", revs[0].SerialHex, serialHex)
	}
}

func TestNextCRLNumber_Monotonic(t *testing.T) {
	d := newTestDB(t)
	n1 := d.NextCRLNumber()
	n2 := d.NextCRLNumber()
	n3 := d.NextCRLNumber()
	if n1 >= n2 || n2 >= n3 {
		t.Errorf("CRL numbers not monotonically increasing: %d, %d, %d", n1, n2, n3)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")

	cert := makeCert(t, 7)

	// Write
	d1, err := Open(path)
	if err != nil {
		t.Fatalf("Open (write): %v", err)
	}
	if err := d1.SaveIssuedCert(cert, "host-a"); err != nil {
		t.Fatalf("SaveIssuedCert: %v", err)
	}
	if err := d1.AddRevocation(cert.SerialNumber.Text(16), time.Now().UTC(), 0); err != nil {
		t.Fatalf("AddRevocation: %v", err)
	}

	// Re-open
	d2, err := Open(path)
	if err != nil {
		t.Fatalf("Open (read): %v", err)
	}
	if _, ok := d2.GetIssuedByHostname("host-a"); !ok {
		t.Error("issued cert not persisted")
	}
	if len(d2.ListRevocations()) != 1 {
		t.Errorf("expected 1 revocation after reload, got %d", len(d2.ListRevocations()))
	}
}
