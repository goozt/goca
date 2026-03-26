package db

import (
	"encoding/gob"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

type DB struct {
	mu   sync.RWMutex
	path string
	s    state
}

var caDB *DB

func init() {
	var err error
	caDB, err = Open(filepath.Join(utils.GetRootCertDir(), "ca.db"))
	if err != nil {
		log.Fatal(err)
	}
}

func GetDB() *DB {
	if caDB == nil {
		log.Fatal("database not initialized")
	}
	return caDB
}

func Open(path string) (*DB, error) {
	d := &DB{path: path, s: state{
		Issued:  make(map[string]IssuedCert),
		Revoked: make(map[string]Revocation),
	}}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return d, nil // new empty DB
		}
		return nil, err
	}
	defer f.Close()

	dec := gob.NewDecoder(f)
	if err := dec.Decode(&d.s); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DB) persistLocked() error {
	tmp := d.path + ".tmp"

	if err := os.MkdirAll(filepath.Dir(d.path), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	enc := gob.NewEncoder(f)
	if err := enc.Encode(d.s); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, d.path)
}
