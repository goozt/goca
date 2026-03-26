package db

import "time"

type IssuedCert struct {
	Hostname  string
	SerialHex string
	NotAfter  time.Time
}

type Revocation struct {
	SerialHex string
	Time      time.Time
	Reason    int
}

type state struct {
	Issued     map[string]IssuedCert // key: hostname
	Revoked    map[string]Revocation // key: serialHex
	NextCRLNum uint64
}
