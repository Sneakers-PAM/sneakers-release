// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

// An invented root key and seed: nothing here is used outside these tests.
var (
	testRoot = bytes.Repeat([]byte{0x42}, 32)
	testSeed = "example-dev-seed"
)

func mustRing(t *testing.T) (*Keyring, []KeyringRow) {
	t.Helper()
	k1 := bytes.Repeat([]byte{0x01}, 32)
	k2 := bytes.Repeat([]byte{0x02}, 32)
	rows := []KeyringRow{
		{Ref: "kek-v1", WrappedKey: mustWrap(t, testRoot, k1), RootRef: "root-v1"},
		{Ref: "kek-v2", WrappedKey: mustWrap(t, testRoot, k2), RootRef: "root-v1", Active: true},
	}
	ring, err := LoadKeyring(rows, testRoot, testSeed)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	return ring, rows
}

func mustWrap(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	out, err := wrap(key, plain)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	return out
}

func TestSealOpenRoundTripUnderActiveRef(t *testing.T) {
	ring, _ := mustRing(t)
	fields := map[string]string{"username": "svc-backup", "password": "pa=ss\nword=="}
	rec, err := ring.Seal(fields)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if rec.KeyRef != "kek-v2" {
		t.Fatalf("KeyRef = %q, want the active kek-v2", rec.KeyRef)
	}
	got, err := ring.Open(rec)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got["username"] != fields["username"] || got["password"] != fields["password"] || len(got) != 2 {
		t.Fatalf("Open = %v, want the sealed fields byte for byte", got)
	}
}

func TestOpenRecordUnderOlderAndLegacyRefs(t *testing.T) {
	ring, _ := mustRing(t)
	for _, ref := range []string{"kek-v1", DevStaticRef} {
		rec, err := ring.SealWith(ref, map[string]string{"password": "old-" + ref})
		if err != nil {
			t.Fatalf("SealWith %s: %v", ref, err)
		}
		got, err := ring.Open(rec)
		if err != nil {
			t.Fatalf("Open %s: %v", ref, err)
		}
		if got["password"] != "old-"+ref {
			t.Fatalf("%s: got %q", ref, got["password"])
		}
	}
}

// The stored form is the original vault's: JSON with Go field names and
// base64 byte fields; a DEK wrapped as nonce||AES-GCM; each field sealed with
// its name as additional data.
func TestStoredFormMatchesTheOriginalLayout(t *testing.T) {
	ring, _ := mustRing(t)
	rec, err := ring.Seal(map[string]string{"password": "x"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"WrappedDEK", "KeyRef", "Fields"} {
		if _, ok := generic[k]; !ok {
			t.Fatalf("stored record lacks %q: %s", k, raw)
		}
	}
	f := generic["Fields"].(map[string]any)["password"].(map[string]any)
	if _, ok := f["Nonce"]; !ok {
		t.Fatalf("field lacks Nonce: %s", raw)
	}
	// Decrypt by hand to pin the layout independently of Open.
	k2 := bytes.Repeat([]byte{0x02}, 32)
	dek := gcmOpen(t, k2, rec.WrappedDEK[:12], rec.WrappedDEK[12:], nil)
	s := rec.Fields["password"]
	if got := gcmOpen(t, dek, s.Nonce, s.Ciphertext, []byte("password")); string(got) != "x" {
		t.Fatalf("hand decrypt = %q", got)
	}
	devKey := sha256.Sum256([]byte(testSeed))
	if !bytes.Equal(ring.keys[DevStaticRef], devKey[:]) {
		t.Fatal("dev-static key must be sha256 of the seed")
	}
}

func gcmOpen(t *testing.T, key, nonce, ct, ad []byte) []byte {
	t.Helper()
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := g.Open(nil, nonce, ct, ad)
	if err != nil {
		t.Fatalf("gcm open: %v", err)
	}
	return out
}

func TestLoadKeyringRefusesWrongRoot(t *testing.T) {
	_, rows := mustRing(t)
	_, err := LoadKeyring(rows, bytes.Repeat([]byte{0x43}, 32), "")
	if !errors.Is(err, ErrKeyring) {
		t.Fatalf("err = %v, want ErrKeyring", err)
	}
}

func TestLoadKeyringNeedsAThirtyTwoByteRoot(t *testing.T) {
	if _, err := LoadKeyring(nil, []byte("short"), ""); !errors.Is(err, ErrKeyring) {
		t.Fatalf("err = %v, want ErrKeyring", err)
	}
}

func TestOpenUnknownRefAndTamper(t *testing.T) {
	ring, _ := mustRing(t)
	rec, err := ring.Seal(map[string]string{"password": "x"})
	if err != nil {
		t.Fatal(err)
	}
	unknown := rec
	unknown.KeyRef = "kek-v9"
	if _, err := ring.Open(unknown); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("unknown ref: err = %v", err)
	}
	tampered := rec
	s := tampered.Fields["password"]
	s.Ciphertext = append([]byte{}, s.Ciphertext...)
	s.Ciphertext[0] ^= 0xff
	tampered.Fields = map[string]Sealed{"password": s}
	if _, err := ring.Open(tampered); err == nil {
		t.Fatal("tampered field must not open")
	}
}

func TestNoDevStaticKeyWithoutSeed(t *testing.T) {
	_, rows := mustRing(t)
	ring, err := LoadKeyring(rows, testRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.SealWith(DevStaticRef, map[string]string{"a": "b"}); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("err = %v, want ErrUnknownRef", err)
	}
}

func TestParseRootKey(t *testing.T) {
	if _, err := ParseRootKey("bm90LTMyLWJ5dGVz"); err == nil {
		t.Fatal("short key must fail")
	}
	k, err := ParseRootKey("QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=")
	if err != nil || !bytes.Equal(k, testRoot) {
		t.Fatalf("ParseRootKey = %x, %v", k, err)
	}
}
