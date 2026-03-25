package ca

import "errors"

// -----------------------------------------------------------------
// Error helpers (optional, for clearer error messages)
// -----------------------------------------------------------------
var (
	ErrUnsupportedKeyType    = errors.New("unsupported key type")
	ErrInvalidCertificatePEM = errors.New("invalid PEM block type for certificate")
	ErrInvalidKeyPEM         = errors.New("invalid PEM block type for private key")
)
