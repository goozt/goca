package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
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

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, ErrInvalidKeyPEM
	}

	var key crypto.Signer

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 RSA
		k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		key = k

	case "EC PRIVATE KEY":
		// SEC1 EC
		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		key = k

	case "PRIVATE KEY":
		// PKCS#8 (could be RSA or ECDSA)
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, nil, ErrInvalidKeyPEM
		}
		key = s

	default:
		return nil, nil, ErrInvalidKeyPEM
	}

	return cert, key, nil
}
