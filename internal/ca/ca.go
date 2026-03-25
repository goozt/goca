package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

func CreateCACertTemplate(subject CertSubject) CertTemplate {
	return func(subjectKeyID []byte, authorityKeyID ...[]byte) *x509.Certificate {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

		now := time.Now()
		years := 15

		return &x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subject.GetName(),
			SubjectKeyId:          subjectKeyID,
			NotBefore:             now.Add(-5 * time.Minute).UTC(),
			NotAfter:              now.AddDate(years, 0, 0).UTC(),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}
	}
}

func CreateCACertificate(template CertTemplate, priv crypto.Signer) (*x509.Certificate, error) {
	pub := priv.Public()
	subjectKeyID, err := getSubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	_template := template(subjectKeyID)
	certDER, err := x509.CreateCertificate(rand.Reader, _template, _template, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}
