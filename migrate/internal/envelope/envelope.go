// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package envelope reads and writes the original vault's sealed records: each
// field sealed with AES-256-GCM under a per-record data key (DEK), with the
// field name as additional data, and the DEK wrapped by a working key named by
// the record's KeyRef. Working keys come from the key ring, each wrapped by the
// root key. Plaintext only ever lives in memory.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// DevStaticRef names the legacy working key derived from the development seed
// (sha256 of the seed). Records sealed before the key ring existed carry it.
const DevStaticRef = "dev-static-v1"

var (
	// ErrKeyring reports a root key that can't open the key ring.
	ErrKeyring = errors.New("envelope: key ring")
	// ErrUnknownRef reports a record sealed under a working key the ring lacks.
	ErrUnknownRef = errors.New("envelope: unknown key ref")
)

// Sealed is one field's AES-256-GCM ciphertext and nonce.
type Sealed struct {
	Nonce      []byte
	Ciphertext []byte
}

// Record is a sealed field set as the vault stores it (JSON, Go field names).
type Record struct {
	WrappedDEK []byte
	KeyRef     string
	Fields     map[string]Sealed
}

// KeyringRow is one row of the vault's kek_keyring table.
type KeyringRow struct {
	Ref        string
	WrappedKey []byte
	RootRef    string
	Active     bool
}

// Keyring holds the unwrapped working keys, by ref.
type Keyring struct {
	keys   map[string][]byte
	active string
}

// ParseRootKey decodes a base64 root key and checks it is 32 bytes.
func ParseRootKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: root key is not base64", ErrKeyring)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("%w: root key must be 32 bytes, got %d", ErrKeyring, len(raw))
	}
	return raw, nil
}

// LoadKeyring unwraps every working key under root. A non-empty devSeed also
// loads the legacy dev-static key. Any row root can't open fails the load, and
// errors name refs only, never key material.
func LoadKeyring(rows []KeyringRow, root []byte, devSeed string) (*Keyring, error) {
	if len(root) != 32 {
		return nil, fmt.Errorf("%w: root key must be 32 bytes", ErrKeyring)
	}
	kr := &Keyring{keys: make(map[string][]byte, len(rows)+1)}
	for _, r := range rows {
		k, err := unwrap(root, r.WrappedKey)
		if err != nil {
			return nil, fmt.Errorf("%w: root key cannot open generation %s (root %s)", ErrKeyring, r.Ref, r.RootRef)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("%w: generation %s is not a 32-byte key", ErrKeyring, r.Ref)
		}
		kr.keys[r.Ref] = k
		if r.Active {
			kr.active = r.Ref
		}
	}
	if devSeed != "" {
		k := sha256.Sum256([]byte(devSeed))
		kr.keys[DevStaticRef] = k[:]
	}
	return kr, nil
}

// Refs lists the working keys the ring holds.
func (k *Keyring) Refs() []string {
	out := make([]string, 0, len(k.keys))
	for r := range k.keys {
		out = append(out, r)
	}
	return out
}

// Open decrypts every field of rec.
func (k *Keyring) Open(rec Record) (map[string]string, error) {
	wk, ok := k.keys[rec.KeyRef]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownRef, rec.KeyRef)
	}
	dek, err := unwrap(wk, rec.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap data key under %s: %w", rec.KeyRef, err)
	}
	g, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rec.Fields))
	for name, s := range rec.Fields {
		pt, err := g.Open(nil, s.Nonce, s.Ciphertext, []byte(name))
		if err != nil {
			return nil, fmt.Errorf("envelope: field %q does not open: %w", name, err)
		}
		out[name] = string(pt)
	}
	return out, nil
}

// Seal seals fields under the active working key.
func (k *Keyring) Seal(fields map[string]string) (Record, error) {
	if k.active == "" {
		return Record{}, fmt.Errorf("%w: no active generation", ErrKeyring)
	}
	return k.SealWith(k.active, fields)
}

// SealWith seals fields under the named working key. The synthetic source uses
// it to lay down records on older and legacy generations.
func (k *Keyring) SealWith(ref string, fields map[string]string) (Record, error) {
	wk, ok := k.keys[ref]
	if !ok {
		return Record{}, fmt.Errorf("%w: %s", ErrUnknownRef, ref)
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Record{}, err
	}
	g, err := newGCM(dek)
	if err != nil {
		return Record{}, err
	}
	rec := Record{KeyRef: ref, Fields: make(map[string]Sealed, len(fields))}
	for name, v := range fields {
		nonce := make([]byte, g.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return Record{}, err
		}
		rec.Fields[name] = Sealed{Nonce: nonce, Ciphertext: g.Seal(nil, nonce, []byte(v), []byte(name))}
	}
	if rec.WrappedDEK, err = wrap(wk, dek); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// WrapKey wraps a working key under root, as kek_keyring stores it.
func WrapKey(root, key []byte) ([]byte, error) { return wrap(root, key) }

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// wrap returns nonce || AES-256-GCM(key, plain).
func wrap(key, plain []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, nil), nil
}

func unwrap(key, wrapped []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := g.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("wrapped value too short")
	}
	return g.Open(nil, wrapped[:ns], wrapped[ns:], nil)
}
