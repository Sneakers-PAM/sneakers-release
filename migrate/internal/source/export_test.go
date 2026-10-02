// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package source_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/source"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/synth"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/testenv"
)

func TestExportSyntheticSource(t *testing.T) {
	src := testenv.NewSource(t, synth.Options{Users: 8, Secrets: 30, AuditRecords: 50})
	cfg, kf, sum := src.Config, src.Kratos, src.Summary
	b, err := source.Export(context.Background(), cfg, kratos.New(kf.URL), log.Nop())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	for _, tb := range schema.Tables {
		info, ok := b.Manifest.Table(tb.Stream())
		if tb.Carried() {
			if !ok || info.Rows != sum.Rows[tb.Stream()] {
				t.Fatalf("%s: manifest %d rows (present %v), seeded %d", tb.Stream(), info.Rows, ok, sum.Rows[tb.Stream()])
			}
			continue
		}
		if ok {
			t.Fatalf("%s must not travel in the bundle", tb.Stream())
		}
	}
	if k, _ := b.Manifest.Table(schema.KratosStream); k.Rows != sum.Kratos {
		t.Fatalf("kratos identities = %d, want %d", k.Rows, sum.Kratos)
	}
	if b.Manifest.AuditHead.Seq != 50 || b.Manifest.AuditHead.Hash == "" {
		t.Fatalf("audit head = %+v", b.Manifest.AuditHead)
	}
	if len(b.Manifest.Samples) == 0 || len(b.Manifest.SampleKey) != 32 {
		t.Fatalf("samples = %d, key %d bytes", len(b.Manifest.Samples), len(b.Manifest.SampleKey))
	}
	var opened int
	if err := b.Each("vault.secret_versions", func(raw []byte) error {
		var row map[string]json.RawMessage
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		if _, ok := row["record"]; ok {
			t.Fatal("a sealed record left the source unopened")
		}
		if _, ok := row["fields"]; ok {
			opened++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if opened != sum.Rows["vault.secret_versions"] {
		t.Fatalf("opened %d versions, want %d", opened, sum.Rows["vault.secret_versions"])
	}
	if err := b.Each("identity.user_totp", func(raw []byte) error {
		if strings.Contains(string(raw), "encrypted_secret") {
			t.Fatal("a TOTP secret left the source unopened")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var keyring bool
	for _, n := range b.Manifest.NotCarried {
		keyring = keyring || n.Name == "vault.kek_keyring"
	}
	if !keyring {
		t.Fatal("the report must list the source key ring as not carried")
	}
}

func TestExportRefusals(t *testing.T) {
	src := testenv.NewSource(t, synth.Options{Users: 3, Secrets: 4, AuditRecords: 5})
	cfg, kf, dbs := src.Config, src.Kratos, src.DB
	ctx := context.Background()
	kc := kratos.New(kf.URL)

	wrong := cfg
	wrong.RootKey = make([]byte, 32)
	if _, err := source.Export(ctx, wrong, kc, log.Nop()); !hasCode(err, codes.SourceValue) {
		t.Fatalf("wrong root key: err = %v, want SourceValue", err)
	}

	if _, err := dbs[schema.Audit].Querier().Exec(ctx, "UPDATE audit_records SET subject = 'edited' WHERE seq = 3"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Export(ctx, cfg, kc, log.Nop()); !hasCode(err, codes.SourceChain) {
		t.Fatalf("tampered chain: err = %v, want SourceChain", err)
	}

	if _, err := dbs[schema.Workflow].Querier().Exec(ctx, "UPDATE "+schema.VersionTable(schema.Workflow)+" SET version = 2"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Export(ctx, cfg, kc, log.Nop()); !hasCode(err, codes.SourceVersion) {
		t.Fatalf("unknown version: err = %v, want SourceVersion", err)
	}
}

func hasCode(err error, want int) bool {
	c, ok := codes.Of(err)
	return ok && c == want
}
