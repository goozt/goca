package db

import (
	"crypto/x509"
	"time"
)

// Save issued cert when you create it
func (d *DB) SaveIssuedCert(c *x509.Certificate, hostname string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	serialHex := c.SerialNumber.Text(16)
	d.s.Issued[hostname] = IssuedCert{
		Hostname:  hostname,
		SerialHex: serialHex,
		NotAfter:  c.NotAfter,
	}
	return d.persistLocked()
}

// Find issued cert (e.g. before revoking)
func (d *DB) GetIssuedByHostname(hostname string) (IssuedCert, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	ic, ok := d.s.Issued[hostname]
	return ic, ok
}

func (d *DB) AddRevocation(serialHex string, when time.Time, reason int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.s.Revoked[serialHex] = Revocation{
		SerialHex: serialHex,
		Time:      when,
		Reason:    reason,
	}
	return d.persistLocked()
}

func (d *DB) ListRevocations() []Revocation {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Revocation, 0, len(d.s.Revoked))
	for _, r := range d.s.Revoked {
		out = append(out, r)
	}
	return out
}

func (d *DB) ListIssued() []IssuedCert {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]IssuedCert, 0, len(d.s.Issued))
	for _, ic := range d.s.Issued {
		out = append(out, ic)
	}
	return out
}

func (d *DB) IsRevoked(serialHex string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, revoked := d.s.Revoked[serialHex]
	return revoked
}

func (d *DB) IsIssued(hostname string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, issued := d.s.Issued[hostname]
	return issued
}

func (d *DB) GetCRLNumber() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.s.NextCRLNum
}

func (d *DB) NextCRLNumber() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.s.NextCRLNum++
	_ = d.persistLocked()
	return d.s.NextCRLNum
}
