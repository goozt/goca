package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

type CRLUpdate struct {
	Number     *big.Int
	ThisUpdate time.Time
	NextUpdate time.Time
}

func SignCertificate(template, parent *x509.Certificate, pub any, priv any) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func SignCSR(template *x509.Certificate, csr *x509.CertificateRequest, parent *x509.Certificate, priv any) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, csr.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func BuildCRL(revoked []*x509.Certificate) ([]pkix.RevokedCertificate, error) {
	revokedEntries := make([]pkix.RevokedCertificate, 0, len(revoked))
	now := time.Now()
	for _, c := range revoked {
		revokedEntries = append(revokedEntries, pkix.RevokedCertificate{
			SerialNumber:   c.SerialNumber,
			RevocationTime: now,
		})
	}

	return revokedEntries, nil
}

func SignCRL(revokedCerts []*x509.Certificate, crlupdate CRLUpdate, parent *x509.Certificate, priv crypto.Signer) ([]byte, error) {
	revokedList, err := BuildCRL(revokedCerts)
	if err != nil {
		return nil, err
	}

	if crlupdate.Number == nil {
		return nil, fmt.Errorf("crl number must be provided for CRL generation")
	}

	if len(revokedList) == 0 {
		return nil, fmt.Errorf("no revoked certificates provided for CRL generation")
	}

	rl := &x509.RevocationList{
		SignatureAlgorithm:  parent.SignatureAlgorithm,
		RevokedCertificates: revokedList,
		Number:              crlupdate.Number,
		ThisUpdate:          revokedList[0].RevocationTime,
		NextUpdate:          crlupdate.NextUpdate,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, rl, parent, priv)
	if err != nil {
		return nil, err
	}
	return crlBytes, nil
}
