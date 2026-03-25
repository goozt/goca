package ca

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type CertTemplate func(subjectKeyID []byte, authorityKeyID ...[]byte) *x509.Certificate

type CertSubject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	PinCode            string
}

func NewCertSubject(commonName string) (CertSubject, error) {
	if strings.TrimSpace(commonName) == "" {
		return CertSubject{}, fmt.Errorf("common name cannot be empty")
	}
	return CertSubject{CommonName: commonName}, nil
}

func (s CertSubject) GetName() pkix.Name {
	var subject pkix.Name
	if s.CommonName == "" {
		subject.CommonName = "Example Common Name"
	} else {
		subject.CommonName = s.CommonName
	}
	if s.Organization != "" {
		subject.Organization = []string{s.Organization}
	}
	if s.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{s.OrganizationalUnit}
	}
	if s.Country != "" {
		subject.Country = []string{s.Country}
	}
	if s.Province != "" {
		subject.Province = []string{s.Province}
	}
	if s.Locality != "" {
		subject.Locality = []string{s.Locality}
	}
	if s.PinCode != "" {
		subject.PostalCode = []string{s.PinCode}
	}
	return subject
}

func getSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki)
	return sum[:], nil
}

func CheckCAExists(dir string) bool {
	caCertPath := filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		slog.Info("CA certificate does not exist", "path", caCertPath)
		return false
	} else if err != nil {
		slog.Error("error checking CA certificate", "path", caCertPath, "error", err)
		return false
	}
	caKeyPath := filepath.Join(dir, "ca.key")
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		slog.Info("CA key does not exist", "path", caKeyPath)
		return false
	} else if err != nil {
		slog.Error("error checking CA key", "path", caKeyPath, "error", err)
		return false
	}
	slog.Info("CA certificate exists", "path", caCertPath)
	return true
}
