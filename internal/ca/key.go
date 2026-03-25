package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func GenerateECDSAKey(curve ...elliptic.Curve) (*ecdsa.PrivateKey, error) {
	c := elliptic.P256()
	if len(curve) > 0 && curve[0] != nil {
		c = curve[0]
	}
	return ecdsa.GenerateKey(c, rand.Reader)
}

func GenerateCAKey() (crypto.Signer, error) {
	return GenerateECDSAKey(elliptic.P384())
}
