// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package totpcipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

var testKey = bytes.Repeat([]byte{0x07}, 32)

func TestParseKeyHexOrBase64(t *testing.T) {
	for _, s := range []string{hex.EncodeToString(testKey), base64.StdEncoding.EncodeToString(testKey)} {
		c, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if c == nil {
			t.Fatal("nil cipher")
		}
	}
	for _, bad := range []string{"", "abcd", base64.StdEncoding.EncodeToString([]byte("sixteen-bytes-ok"))} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("Parse(%q): want an error", bad)
		}
	}
}

func TestSealOpenAndTheStoredForm(t *testing.T) {
	c, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Open(sealed)
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("stored form must be std base64: %v", err)
	}
	b, _ := aes.NewCipher(testKey)
	g, _ := cipher.NewGCM(b)
	pt, err := g.Open(nil, raw[:12], raw[12:], nil)
	if err != nil || string(pt) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("stored form must be nonce||gcm: %q, %v", pt, err)
	}
	other, _ := New(bytes.Repeat([]byte{0x08}, 32))
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("wrong key must not open")
	}
}
