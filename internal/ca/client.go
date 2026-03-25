package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

func CreateClientCertTemplate(subject CertSubject) CertTemplate {
	return func(subjectKeyID []byte, authorityKeyID ...[]byte) *x509.Certificate {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

		now := time.Now()
		year, month, days := 1, 0, 0

		return &x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subject.GetName(),
			SubjectKeyId:          subjectKeyID,
			AuthorityKeyId:        authorityKeyID[0],
			NotBefore:             now.Add(-5 * time.Minute).UTC(),
			NotAfter:              now.AddDate(year, month, days).UTC(),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
			MaxPathLen:            0,
		}
	}
}

func CreateClientCertificate(template CertTemplate, interCaCert *x509.Certificate, interCaKey crypto.Signer, priv crypto.Signer) (*x509.Certificate, error) {
	pub := priv.Public()
	subjectKeyID, err := getSubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	_template := template(subjectKeyID, interCaCert.AuthorityKeyId)
	certDER, err := x509.CreateCertificate(rand.Reader, _template, interCaCert, pub, interCaKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}
