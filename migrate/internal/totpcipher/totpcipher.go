// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package totpcipher reads and writes the identity service's at-rest form of a
// TOTP shared secret: base64(nonce || AES-256-GCM) under TOTP_ENC_KEY, a
// 32-byte key given as hex or standard base64.
package totpcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Cipher seals and opens TOTP secrets under one key.
type Cipher struct{ aead cipher.AEAD }

// New returns a Cipher for a raw 32-byte key.
func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("totp key must be 32 bytes, got %d", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: g}, nil
}

// Parse decodes a key given as 64 hex characters or base64 of 32 bytes.
func Parse(s string) (*Cipher, error) {
	if raw, err := hex.DecodeString(s); err == nil && len(raw) == 32 {
		return New(raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return New(raw)
	}
	return nil, errors.New("totp key must decode (hex or base64) to 32 bytes")
}

// Seal returns base64(nonce || ciphertext) of plain.
func (c *Cipher) Seal(plain string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(c.aead.Seal(nonce, nonce, []byte(plain), nil)), nil
}

// Open reverses Seal.
func (c *Cipher) Open(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", errors.New("totp secret is not base64")
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("totp secret too short")
	}
	pt, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", errors.New("totp secret does not open under this key")
	}
	return string(pt), nil
}
