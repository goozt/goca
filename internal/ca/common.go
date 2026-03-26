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

	"github.com/goozt/gopgbase/infra/ca/internal/utils"
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

func CheckRootCAExists(dir string) bool {
	dir = utils.GetRootCertDir()
	rootCACertPath := filepath.Join(dir, "rootCA.crt")
	if _, err := os.Stat(rootCACertPath); os.IsNotExist(err) {
		slog.Info("Root CA certificate does not exist", "path", rootCACertPath)
		return false
	} else if err != nil {
		slog.Error("error checking Root CA certificate", "path", rootCACertPath, "error", err)
		return false
	}
	rootCAKeyPath := filepath.Join(dir, "rootCA.key")
	if _, err := os.Stat(rootCAKeyPath); os.IsNotExist(err) {
		slog.Info("Root CA key does not exist", "path", rootCAKeyPath)
		return false
	} else if err != nil {
		slog.Error("error checking Root CA key", "path", rootCAKeyPath, "error", err)
		return false
	}
	slog.Info("Root CA certificate exists", "path", rootCACertPath)
	return true
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

func CheckClientRootCertExists(dir string) bool {
	clientCertPath := filepath.Join(dir, "client.root.crt")
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		slog.Info("Client Root certificate does not exist", "path", clientCertPath)
		return false
	} else if err != nil {
		slog.Error("error checking Client Root certificate", "path", clientCertPath, "error", err)
		return false
	}
	clientKeyPath := filepath.Join(dir, "client.root.key")
	if _, err := os.Stat(clientKeyPath); os.IsNotExist(err) {
		slog.Info("Client Root key does not exist", "path", clientKeyPath)
		return false
	} else if err != nil {
		slog.Error("error checking Client key", "path", clientKeyPath, "error", err)
		return false
	}
	slog.Info("Client Root certificate exists", "path", clientCertPath)
	return true
}
