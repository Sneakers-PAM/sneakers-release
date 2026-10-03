// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
)

func sample(t *testing.T) *Bundle {
	t.Helper()
	b := New("profile-test")
	s := b.Stream("vault.secrets")
	for _, row := range []map[string]any{{"id": "sec-1", "fields": map[string]string{"password": "Hunter-2-Plaintext"}}, {"id": "sec-2"}} {
		if err := s.Add(row); err != nil {
			t.Fatal(err)
		}
	}
	b.Stream("audit.audit_records")
	b.Manifest.AuditHead = Head{Seq: 0}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return b
}

func keys(t *testing.T) (*age.X25519Identity, *age.X25519Identity) {
	t.Helper()
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestRoundTrip(t *testing.T) {
	id, _ := keys(t)
	var buf bytes.Buffer
	in := sample(t)
	if err := Write(&buf, in, id.Recipient()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("Hunter-2-Plaintext")) || bytes.Contains(buf.Bytes(), []byte("sec-1")) {
		t.Fatal("the encrypted bundle carries plaintext")
	}
	out, err := Read(&buf, id)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.Manifest.BundleID != in.Manifest.BundleID || out.Manifest.Profile != "profile-test" {
		t.Fatalf("manifest = %+v", out.Manifest)
	}
	tbl, ok := out.Manifest.Table("vault.secrets")
	if !ok || tbl.Rows != 2 || tbl.SHA256 == "" {
		t.Fatalf("table info = %+v, %v", tbl, ok)
	}
	var rows []map[string]any
	if err := out.Each("vault.secrets", func(raw []byte) error {
		var m map[string]any
		if err := decode(raw, &m); err != nil {
			return err
		}
		rows = append(rows, m)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["id"] != "sec-1" {
		t.Fatalf("rows = %v", rows)
	}
	if _, ok := out.Manifest.Table("audit.audit_records"); !ok {
		t.Fatal("an empty table still gets a manifest entry")
	}
}

func TestWrongKeyIsRefused(t *testing.T) {
	id, other := keys(t)
	var buf bytes.Buffer
	if err := Write(&buf, sample(t), id.Recipient()); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(&buf, other); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestTamperedStreamFailsItsChecksum(t *testing.T) {
	b := sample(t)
	b.streams["vault.secrets"].buf.WriteString(`{"id":"sec-3"}` + "\n")
	if err := b.check(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v, want ErrIntegrity", err)
	}
}

func TestStreamMissingFromManifestIsRefused(t *testing.T) {
	b := sample(t)
	b.Manifest.Tables = b.Manifest.Tables[:1]
	if err := b.check(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v, want ErrIntegrity", err)
	}
}

func TestOtherMajorVersionIsRefused(t *testing.T) {
	id, _ := keys(t)
	b := sample(t)
	b.Manifest.FormatVersion = "2.0"
	var buf bytes.Buffer
	if err := Write(&buf, b, id.Recipient()); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(&buf, id); !errors.Is(err, ErrVersion) {
		t.Fatalf("err = %v, want ErrVersion", err)
	}
	b.Manifest.FormatVersion = "1.7"
	buf.Reset()
	if err := Write(&buf, b, id.Recipient()); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(&buf, id); err != nil {
		t.Fatalf("a newer minor of the same major reads: %v", err)
	}
}

func TestStreamNamesAreChecked(t *testing.T) {
	b := New("p")
	for _, bad := range []string{"", "../x", "a/b", "UPPER.case"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("Stream(%q) must panic: names are fixed in code", bad)
				}
			}()
			b.Stream(bad)
		}()
	}
}

func TestParseRecipientAndIdentity(t *testing.T) {
	id, _ := keys(t)
	if _, err := ParseRecipient(id.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRecipient("age1notakey"); err == nil {
		t.Fatal("bad recipient must fail")
	}
	got, err := ParseIdentities(strings.NewReader("# created: test\n" + id.String() + "\n"))
	if err != nil || len(got) != 1 {
		t.Fatalf("ParseIdentities = %v, %v", got, err)
	}
}
