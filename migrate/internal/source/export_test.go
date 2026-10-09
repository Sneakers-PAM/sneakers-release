// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package source_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
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

// The appliance migration carries each secret's current value only and
// resets every sign-in: no password hashes, TOTP seeds or passkeys travel.
func TestExportCurrentOnlyAndSignInReset(t *testing.T) {
	src := testenv.NewSource(t, synth.Options{Users: 6, Secrets: 24, AuditRecords: 20})
	cfg := src.Config
	cfg.CurrentOnly, cfg.ResetSignIn = true, true
	cfg.TOTP = nil // not needed: no TOTP seed is opened
	b, err := source.Export(context.Background(), cfg, kratos.New(src.Kratos.URL), log.Nop())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if !b.Manifest.CurrentOnly || !b.Manifest.SignInReset {
		t.Fatalf("manifest current_only %v, sign_in_reset %v", b.Manifest.CurrentOnly, b.Manifest.SignInReset)
	}
	per := map[string]int{}
	if err := b.Each("vault.secret_versions", func(raw []byte) error {
		var row struct {
			SecretID string `json:"secret_id"`
			Active   bool   `json:"active"`
			Staged   bool   `json:"staged"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		if !row.Active || row.Staged {
			t.Fatalf("version of %s carried that isn't the current one", row.SecretID)
		}
		per[row.SecretID]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	secrets, _ := b.Manifest.Table("vault.secrets")
	if len(per) != secrets.Rows {
		t.Fatalf("%d secrets carry a version, want all %d", len(per), secrets.Rows)
	}
	for id, n := range per {
		if n != 1 {
			t.Fatalf("%s carries %d versions, want 1", id, n)
		}
	}
	for _, s := range b.Manifest.Samples {
		if s.Version != 0 {
			var active bool
			_ = b.Each("vault.secret_versions", func(raw []byte) error {
				var row struct {
					SecretID  string `json:"secret_id"`
					VersionNo int    `json:"version_no"`
				}
				_ = json.Unmarshal(raw, &row)
				active = active || (row.SecretID == s.SecretID && row.VersionNo == s.Version)
				return nil
			})
			if !active {
				t.Fatalf("sample %s@%d names a version the bundle doesn't carry", s.SecretID, s.Version)
			}
		}
	}
	for _, stream := range []string{"identity.user_totp", "identity.user_webauthn_credentials"} {
		if tb, ok := b.Manifest.Table(stream); !ok || tb.Rows != 0 {
			t.Fatalf("%s: present %v with %d rows, want present and empty", stream, ok, tb.Rows)
		}
	}
	if err := b.Each(schema.KratosStream, func(raw []byte) error {
		var id kratos.Identity
		if err := json.Unmarshal(raw, &id); err != nil {
			return err
		}
		if id.PasswordHash() != "" || len(id.Credentials) != 0 {
			t.Fatal("a Kratos identity carries credentials after a sign-in reset")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	notCarried := map[string]int{}
	for _, n := range b.Manifest.NotCarried {
		notCarried[n.Name] = n.Rows
	}
	if notCarried["vault.secret_versions.history"] == 0 || notCarried["identity.user_totp"] == 0 || notCarried["kratos.credentials.password"] == 0 {
		t.Fatalf("not carried = %v", notCarried)
	}
}

// Export counts each category in the source and prints them next to the
// bundle's; the two must agree.
func TestExportParity(t *testing.T) {
	src := testenv.NewSource(t, synth.Options{Users: 5, Secrets: 12, AuditRecords: 10})
	b, err := source.Export(context.Background(), src.Config, kratos.New(src.Kratos.URL), log.Nop())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	want := map[string]int{"folders": src.Summary.Rows["vault.folders"], "secrets": 12, "types": src.Summary.Rows["vault.secret_types"],
		"users": 5, "targets": src.Summary.Rows["vault.targets"], "connections": src.Summary.Rows["vault.connections"]}
	got := map[string]bundle.ParityCount{}
	for _, p := range b.Manifest.Parity {
		got[p.Name] = p
	}
	for name, n := range want {
		p, ok := got[name]
		if !ok || p.Source != n || p.Bundle != n {
			t.Fatalf("parity %s = %+v, want %d in the source and the bundle", name, p, n)
		}
	}
}

// The inventory needs no key and writes no bundle: counts and names only.
func TestInventory(t *testing.T) {
	src := testenv.NewSource(t, synth.Options{Users: 6, Secrets: 20, AuditRecords: 15})
	inv, err := source.Inventory(context.Background(), src.Config.DSN, kratos.New(src.Kratos.URL), log.Nop())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if inv.Tables["vault.secrets"] != 20 || inv.Tables["audit.audit_records"] != 15 || inv.Tables["identity.users"] != 6 || inv.KratosIdentities != src.Summary.Kratos {
		t.Fatalf("inventory = %+v", inv)
	}
	total := 0
	for _, n := range inv.ByType {
		total += n
	}
	if total != 20 || len(inv.ByFolder) == 0 || inv.UsersByRole["site-admin"] == 0 || inv.RotationSchedules == 0 {
		t.Fatalf("by type %v, by folder %v, roles %v, rotations %d", inv.ByType, inv.ByFolder, inv.UsersByRole, inv.RotationSchedules)
	}
	if len(inv.PersonalTokens) != src.Summary.Rows["identity.user_tokens"] {
		t.Fatalf("personal tokens = %v", inv.PersonalTokens)
	}
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rows, err := src.DB[schema.Identity].Querier().Query(ctx, "SELECT token_hash FROM user_tokens UNION ALL SELECT token_hash FROM api_tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		n++
		if strings.Contains(string(raw), h) {
			t.Fatal("the inventory carries a token hash")
		}
	}
	if n == 0 || strings.Contains(string(raw), "wrappedDek") || strings.Contains(string(raw), "-----BEGIN") {
		t.Fatal("the inventory carries sealed material, or the check proved nothing")
	}
}

// A sanitised export keeps the shape and replaces every value, token hash
// and address with a fake.
func TestExportSanitised(t *testing.T) {
	src := testenv.NewSource(t, synth.Options{Users: 5, Secrets: 16, AuditRecords: 10})
	ctx := context.Background()
	real, err := source.Export(ctx, src.Config, kratos.New(src.Kratos.URL), log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	cfg := src.Config
	cfg.Sanitise = true
	fake, err := source.Export(ctx, cfg, kratos.New(src.Kratos.URL), log.Nop())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if !fake.Manifest.Sanitised || !fake.Manifest.SignInReset {
		t.Fatalf("sanitised %v, sign-in reset %v", fake.Manifest.Sanitised, fake.Manifest.SignInReset)
	}
	var secrets []string
	collect := func(stream, col string) {
		_ = real.Each(stream, func(raw []byte) error {
			var row map[string]any
			_ = json.Unmarshal(raw, &row)
			switch v := row[col].(type) {
			case map[string]any:
				for _, x := range v {
					if s := fmt.Sprint(x); len(s) >= 6 {
						secrets = append(secrets, s)
					}
				}
			case string:
				secrets = append(secrets, v)
			}
			return nil
		})
	}
	collect("vault.secret_records", "fields")
	collect("vault.secret_versions", "fields")
	collect("identity.user_tokens", "token_hash")
	collect("identity.api_tokens", "token_hash")
	_ = real.Each("vault.targets", func(raw []byte) error {
		var row struct {
			Data struct {
				Hostname string `json:"hostname"`
			} `json:"data"`
		}
		_ = json.Unmarshal(raw, &row)
		secrets = append(secrets, row.Data.Hostname)
		return nil
	})
	if len(secrets) < 20 {
		t.Fatalf("collected %d values; the check would prove little", len(secrets))
	}
	var all strings.Builder
	for _, n := range fake.Names() {
		_ = fake.Each(n, func(raw []byte) error { all.Write(raw); return nil })
	}
	for _, v := range secrets {
		if strings.Contains(all.String(), v) {
			t.Fatalf("a real value survived sanitising (%d chars)", len(v))
		}
	}
	for _, stream := range []string{"vault.secrets", "vault.folders", "identity.users", "vault.targets"} {
		a, _ := real.Manifest.Table(stream)
		b, _ := fake.Manifest.Table(stream)
		if a.Rows != b.Rows {
			t.Fatalf("%s: %d rows sanitised, %d real", stream, b.Rows, a.Rows)
		}
	}
}
