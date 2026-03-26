package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// PemEncode returns PEM‑encoded bytes for a certificate or private key.
func PemEncode(blockType string, derBytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: derBytes})
}

func PemEncodeCertificate(cert *x509.Certificate) []byte {
	return PemEncode("CERTIFICATE", cert.Raw)
}

func PemEncodePrivateKey(priv crypto.Signer) ([]byte, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return PemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k)), nil
	case *ecdsa.PrivateKey:
		derBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return PemEncode("EC PRIVATE KEY", derBytes), nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// WritePEMToFile writes PEM‑encoded data to a file with the given permissions.
func WritePEMToFile(filename string, pemData []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(pemData)
	return err
}

func WriteCertificate(cert *x509.Certificate, filename string) error {
	pemData := PemEncodeCertificate(cert)
	return WritePEMToFile(filename, pemData, 0644)
}

func WritePrivateKey(priv crypto.Signer, filename string) error {
	pemData, err := PemEncodePrivateKey(priv)
	if err != nil {
		return err
	}
	return WritePEMToFile(filename, pemData, 0600)
}

func SaveCertAndKey(cert *x509.Certificate, priv crypto.Signer, certFile, keyFile string) error {
	if err := WriteCertificate(cert, certFile); err != nil {
		return err
	}
	return WritePrivateKey(priv, keyFile)
}

// parsePrivateKeyBlock parses a PEM block into a crypto.Signer.
func parsePrivateKeyBlock(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, ErrInvalidKeyPEM
		}
		return s, nil
	default:
		return nil, ErrInvalidKeyPEM
	}
}

// verifyKeyMatchesCert returns an error if the private key's public half does
// not match the public key embedded in the certificate.
func verifyKeyMatchesCert(cert *x509.Certificate, key crypto.Signer, certFile string) error {
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate public key: %w", err)
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal private key public key: %w", err)
	}
	if string(certPubDER) != string(keyPubDER) {
		return fmt.Errorf("private key does not match certificate public key in %q", certFile)
	}
	return nil
}

func LoadCAFromFiles(certFile, keyFile string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, ErrInvalidCertificatePEM
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil, fmt.Errorf("certificate %q has expired at %s", certFile, cert.NotAfter.UTC().Format(time.RFC3339))
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, ErrInvalidKeyPEM
	}
	key, err := parsePrivateKeyBlock(keyBlock)
	if err != nil {
		return nil, nil, err
	}

	if err := verifyKeyMatchesCert(cert, key, certFile); err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}
