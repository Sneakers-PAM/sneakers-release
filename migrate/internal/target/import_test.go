// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package target_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/chain"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/envelope"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos/kratostest"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/rpc"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/source"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/synth"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/target"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/testenv"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/totpcipher"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/verify"
)

// fakeVault stands in for the target vault: it seals under its own key ring
// and audits each call (as SealForImport does), and reads back from the target
// vault database.
type fakeVault struct {
	ring  *envelope.Keyring
	db    *postgres.DB
	audit *fakeAudit
	calls int
}

func newFakeVault(t *testing.T, db *postgres.DB) *fakeVault {
	t.Helper()
	root, wk := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(root)
	_, _ = rand.Read(wk)
	wrapped, err := envelope.WrapKey(root, wk)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := envelope.LoadKeyring([]envelope.KeyringRow{{Ref: "kek-v1", WrappedKey: wrapped, RootRef: "root-v1", Active: true}}, root, "")
	if err != nil {
		t.Fatal(err)
	}
	return &fakeVault{ring: ring, db: db}
}

func (f *fakeVault) Seal(ctx context.Context, items []map[string]string) ([][]byte, error) {
	f.calls++
	if f.audit != nil {
		if err := f.audit.Record(ctx, rpc.Event{Action: "vault.import.seal", Actor: "system:sneakers-migrate"}); err != nil {
			return nil, err
		}
	}
	out := make([][]byte, 0, len(items))
	for _, it := range items {
		rec, err := f.ring.Seal(it)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

func (f *fakeVault) Reveal(ctx context.Context, id string, field string) (string, error) {
	var raw []byte
	if err := f.db.Querier().QueryRow(ctx, "SELECT record FROM secret_records WHERE secret_id = $1", id).Scan(&raw); err != nil {
		return "", err
	}
	var rec envelope.Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return "", err
	}
	fields, err := f.ring.Open(rec)
	if err != nil {
		return "", err
	}
	return fields[field], nil
}

func (f *fakeVault) Targets(ctx context.Context) ([]rpc.Target, error) {
	rows, err := f.db.Querier().Query(ctx, "SELECT id, data->>'hostname', data->>'connectionId' FROM targets")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rpc.Target
	for rows.Next() {
		var t rpc.Target
		if err := rows.Scan(&t.ID, &t.Hostname, &t.ConnectionID); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (f *fakeVault) Connections(ctx context.Context) ([]rpc.Connection, error) {
	rows, err := f.db.Querier().Query(ctx, "SELECT id, data->>'protocol', coalesce(data->>'privilegedSecretId', '') FROM connections")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rpc.Connection
	for rows.Next() {
		var c rpc.Connection
		if err := rows.Scan(&c.ID, &c.Protocol, &c.PrivilegedSecretID); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (f *fakeVault) SecretExists(ctx context.Context, id string) (bool, error) {
	var n int
	err := f.db.Querier().QueryRow(ctx, "SELECT count(*) FROM secrets WHERE id = $1", id).Scan(&n)
	return n == 1, err
}

// fakeAudit appends and verifies like the audit service, on the target audit
// database.
type fakeAudit struct{ db *postgres.DB }

func (a *fakeAudit) Record(ctx context.Context, e rpc.Event) error {
	q := a.db.Querier()
	var seq int64
	var prev string
	err := q.QueryRow(ctx, "SELECT seq, hash FROM audit_records ORDER BY seq DESC LIMIT 1").Scan(&seq, &prev)
	if err != nil && err != postgres.ErrNoRows {
		return err
	}
	r := chain.Record{Seq: uint64(seq + 1), Tier: 1, Action: e.Action, ActorUserID: e.Actor, Subject: e.Subject, Attributes: e.Attributes, OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), PrevHash: prev}
	r.Hash = chain.Hash(r)
	attrs, _ := json.Marshal(r.Attributes)
	_, err = q.Exec(ctx, "INSERT INTO audit_records (seq, tier, action, actor_user_id, subject, group_id, sensitive, attributes, occurred_at, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,'',false,$6,$7,$8,$9)",
		int64(r.Seq), r.Tier, r.Action, r.ActorUserID, r.Subject, attrs, r.OccurredAt, r.PrevHash, r.Hash)
	return err
}

func (a *fakeAudit) VerifyChain(ctx context.Context) (bool, uint64, uint64, error) {
	rows, err := a.db.Querier().Query(ctx, "SELECT row_to_json(t)::text FROM audit_records t ORDER BY seq")
	if err != nil {
		return false, 0, 0, err
	}
	defer rows.Close()
	var recs []chain.Record
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return false, 0, 0, err
		}
		var r chain.Record
		if err := json.Unmarshal([]byte(s), &r); err != nil {
			return false, 0, 0, err
		}
		recs = append(recs, r)
	}
	ok, at := chain.Verify(recs)
	return ok, at, uint64(len(recs)), rows.Err()
}

type rig struct {
	src    *testenv.Source
	bundle *bundle.Bundle
	dsn    map[schema.Service]string
	db     map[schema.Service]*postgres.DB
	vault  *fakeVault
	audit  *fakeAudit
	kratos *kratostest.Server
	totp   *totpcipher.Cipher
}

func newRig(t *testing.T) *rig {
	t.Helper()
	return newRigWith(t, func(*source.Config) {})
}

// newRigWith exports with the source settings changed by set.
func newRigWith(t *testing.T, set func(*source.Config)) *rig {
	t.Helper()
	src := testenv.NewSource(t, synth.Options{Users: 10, Secrets: 40, AuditRecords: 120})
	sc := src.Config
	set(&sc)
	b, err := source.Export(context.Background(), sc, kratos.New(src.Kratos.URL), log.Nop())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Through the encrypted file and back, as the real flow does.
	id, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	if err := bundle.Write(&buf, b, id.Recipient()); err != nil {
		t.Fatal(err)
	}
	b, err = bundle.Read(&buf, id)
	if err != nil {
		t.Fatal(err)
	}
	dsn, dbs := testenv.NewTarget(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	tc, _ := totpcipher.New(key)
	kf := kratostest.New()
	t.Cleanup(kf.Close)
	audit := &fakeAudit{db: dbs[schema.Audit]}
	vault := newFakeVault(t, dbs[schema.Vault])
	vault.audit = audit
	return &rig{src: src, bundle: b, dsn: dsn, db: dbs, vault: vault, audit: audit, kratos: kf, totp: tc}
}

// keepAll is a mapping file that carries everything as it is: an import
// outside rehearsal mode needs one.
var keepAll = mustPlan(`{"format": "sneakers-migrate-mapping", "version": 1, "unlisted": "keep"}`)

func mustPlan(body string) *mapping.Plan {
	p, err := mapping.ParsePlan([]byte(body))
	if err != nil {
		panic(err)
	}
	return p
}

func (r *rig) cfg() target.Config {
	return target.Config{DSN: r.dsn, TOTP: r.totp, Plan: keepAll}
}

func (r *rig) deps() target.Deps {
	return target.Deps{Sealer: r.vault, Recorder: r.audit, Kratos: kratos.New(r.kratos.URL)}
}

func (r *rig) importIt(t *testing.T, cfg target.Config) (*target.Outcome, error) {
	t.Helper()
	return target.Import(context.Background(), cfg, r.bundle, r.deps(), log.Nop())
}

func (r *rig) verifyIt(t *testing.T) bool {
	t.Helper()
	return r.verifyReport(t).OK
}

func (r *rig) verifyReport(t *testing.T) *report.Verify {
	t.Helper()
	return r.verifyWith(t, verify.Config{DSN: r.dsn, Plan: keepAll})
}

func (r *rig) verifyWith(t *testing.T, cfg verify.Config) *report.Verify {
	t.Helper()
	rep, err := verify.Run(context.Background(), cfg, r.bundle, r.vault, r.audit, kratos.New(r.kratos.URL), log.Nop())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var sb strings.Builder
	if err := rep.Text(&sb); err != nil {
		t.Fatal(err)
	}
	t.Log(sb.String())
	return rep
}

func checkOK(t *testing.T, rep *report.Verify, name string) bool {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c.OK
		}
	}
	t.Fatalf("verify has no %q check", name)
	return false
}

func code(err error) int {
	c, _ := codes.Of(err)
	return c
}

func TestImportThenVerify(t *testing.T) {
	r := newRig(t)
	out, err := r.importIt(t, r.cfg())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	rep := out.Report
	for _, c := range rep.Tables {
		want := c.Bundle
		if c.Table == "workflow.approval_comments" {
			want += rep.Closed["approval requests"]
		}
		if c.Expected != want {
			t.Fatalf("%s: expected %d, want %d", c.Table, c.Expected, want)
		}
		if c.Table != "audit.audit_records" && c.Target != want {
			t.Fatalf("%s: target %d, want %d", c.Table, c.Target, want)
		}
	}
	if rep.KratosCreated != r.src.Summary.Kratos || len(rep.UsersWithoutSignIn) != 1 {
		t.Fatalf("kratos created %d (want %d), unlinked %v", rep.KratosCreated, r.src.Summary.Kratos, rep.UsersWithoutSignIn)
	}
	if len(rep.SSHTargetsToPin) != 10 || rep.AuditEntries == 0 || out.OwnerPassword != "" {
		t.Fatalf("pins %d, audit entries %d, owner password set %v", len(rep.SSHTargetsToPin), rep.AuditEntries, out.OwnerPassword != "")
	}
	if !r.verifyIt(t) {
		t.Fatal("verify failed after a clean import")
	}
	assertNoValues(t, r.bundle, rep)
	assertSecurityReview(t, rep)

	ctx := context.Background()
	var sealed string
	if err := r.db[schema.Identity].Querier().QueryRow(ctx, "SELECT encrypted_secret FROM user_totp ORDER BY user_id LIMIT 1").Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := r.totp.Open(sealed); err != nil {
		t.Fatalf("TOTP secret does not open under the target key: %v", err)
	}
	var subject string
	if err := r.db[schema.Identity].Querier().QueryRow(ctx, "SELECT subject FROM users WHERE id = 'usr-0001'").Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(subject, "00000000-0000-4000-8000-") {
		t.Fatalf("subject = %q, want the new Kratos id", subject)
	}

	// A second run resumes: nothing written twice, no new audit entries.
	again, err := r.importIt(t, r.cfg())
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	for s, st := range again.Report.Services {
		if !strings.HasPrefix(st, "already imported") {
			t.Fatalf("re-run: %s %s", s, st)
		}
	}
	if again.Report.AuditEntries != 0 || again.Report.KratosCreated != 0 {
		t.Fatalf("re-run appended %d audit entries and created %d identities", again.Report.AuditEntries, again.Report.KratosCreated)
	}
	if !r.verifyIt(t) {
		t.Fatal("verify failed after a resumed import")
	}

	// A tampered audit record fails verify.
	if _, err := r.db[schema.Audit].Querier().Exec(ctx, "UPDATE audit_records SET actor_user_id = 'usr-9999' WHERE seq = 42"); err != nil {
		t.Fatal(err)
	}
	if r.verifyIt(t) {
		t.Fatal("verify passed with a tampered audit record")
	}
}

func TestImportRefusesAForeignTarget(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.db[schema.Identity].Querier().Exec(ctx, "INSERT INTO users (id, name, email) VALUES ('usr-x', 'Someone', 'someone@example.org')"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.importIt(t, r.cfg()); code(err) != codes.TargetNotEmpty {
		t.Fatalf("err = %v, want TargetNotEmpty", err)
	}
	wipe := r.cfg()
	wipe.Wipe = true
	if _, err := r.importIt(t, wipe); code(err) != codes.ModeRefused {
		t.Fatalf("wipe outside rehearsal: err = %v, want ModeRefused", err)
	}
	owner := r.cfg()
	owner.OwnerEmail = "owner@example.org"
	if _, err := r.importIt(t, owner); code(err) != codes.ModeRefused {
		t.Fatalf("owner password outside rehearsal: err = %v, want ModeRefused", err)
	}
	rehearsal := r.cfg()
	rehearsal.Rehearsal, rehearsal.Wipe, rehearsal.OwnerEmail = true, true, "owner@example.org"
	out, err := r.importIt(t, rehearsal)
	if err != nil {
		t.Fatalf("rehearsal import with wipe: %v", err)
	}
	if !out.Report.Wiped || out.OwnerPassword == "" || len(out.OwnerPassword) != 24 {
		t.Fatalf("wiped %v, owner password length %d", out.Report.Wiped, len(out.OwnerPassword))
	}
	ownerID, err := kratos.New(r.kratos.URL).FindByIdentifier(ctx, "owner@example.org")
	if err != nil || r.kratos.Passwords[ownerID] != out.OwnerPassword {
		t.Fatal("the owner's Kratos password was not replaced")
	}
	raw, _ := json.Marshal(out.Report)
	if strings.Contains(string(raw), out.OwnerPassword) {
		t.Fatal("the report carries the owner's password")
	}
	var days string
	if err := r.db[schema.Vault].Querier().QueryRow(ctx, "SELECT coalesce(data->>'kekRotationDays', '0') FROM security_settings").Scan(&days); err != nil || days != "0" {
		t.Fatalf("rehearsal kekRotationDays = %q, %v", days, err)
	}
	if !r.verifyIt(t) {
		t.Fatal("verify failed after a rehearsal import")
	}
}

func TestImportChecksVersionsAndKeys(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	noKey := r.cfg()
	noKey.TOTP = nil
	if _, err := r.importIt(t, noKey); code(err) != codes.TargetKey {
		t.Fatalf("no TOTP key: err = %v, want TargetKey", err)
	}
	if _, err := r.db[schema.Workflow].Querier().Exec(ctx, "UPDATE "+schema.VersionTable(schema.Workflow)+" SET version = 2"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.importIt(t, r.cfg()); code(err) != codes.TargetVersion {
		t.Fatalf("other target version: err = %v, want TargetVersion", err)
	}
}

// Older versions are not revealed: import matches their sample hashes
// against the bundle before sealing and records the count in its audit
// summary, and verify compares each secret's version numbers, timestamps and
// sealed fields with the bundle.
func TestVerifyChecksOlderVersionsWithoutRevealing(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	older := 0
	for _, s := range r.bundle.Manifest.Samples {
		if s.Version > 0 {
			older++
		}
	}
	if older == 0 {
		t.Fatal("the bundle has no older-version samples; the test would prove nothing")
	}
	out, err := r.importIt(t, r.cfg())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if out.Report.VersionSamples != older {
		t.Fatalf("import matched %d older-version samples, want %d", out.Report.VersionSamples, older)
	}
	var matched string
	if err := r.db[schema.Audit].Querier().QueryRow(ctx, "SELECT attributes->>'version_samples_matched' FROM audit_records WHERE action = 'migration.import'").Scan(&matched); err != nil || matched != fmt.Sprint(older) {
		t.Fatalf("audit summary version_samples_matched = %q (%v), want %d", matched, err, older)
	}
	rep := r.verifyReport(t)
	if !rep.OK || !checkOK(t, rep, "versions") {
		t.Fatal("verify failed after a clean import")
	}

	vq := r.db[schema.Vault].Querier()
	var id string
	var no int
	if err := vq.QueryRow(ctx, "SELECT secret_id, version_no FROM secret_versions ORDER BY secret_id, version_no LIMIT 1").Scan(&id, &no); err != nil {
		t.Fatal(err)
	}
	var orig []byte
	if err := vq.QueryRow(ctx, "SELECT record FROM secret_versions WHERE secret_id = $1 AND version_no = $2", id, no).Scan(&orig); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := vq.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	tamper := []struct {
		name     string
		do, undo func()
	}{
		{"a moved timestamp",
			func() {
				exec("UPDATE secret_versions SET created_at = created_at + interval '1 day' WHERE secret_id = $1 AND version_no = $2", id, no)
			},
			func() {
				exec("UPDATE secret_versions SET created_at = created_at - interval '1 day' WHERE secret_id = $1 AND version_no = $2", id, no)
			}},
		{"a renumbered version",
			func() {
				exec("UPDATE secret_versions SET version_no = version_no + 100 WHERE secret_id = $1 AND version_no = $2", id, no)
			},
			func() {
				exec("UPDATE secret_versions SET version_no = $2 WHERE secret_id = $1 AND version_no = $2 + 100", id, no)
			}},
		{"a dropped sealed field",
			func() {
				exec("UPDATE secret_versions SET record = jsonb_set(record, '{Fields}', '{}'::jsonb) WHERE secret_id = $1 AND version_no = $2", id, no)
			},
			func() {
				exec("UPDATE secret_versions SET record = $3 WHERE secret_id = $1 AND version_no = $2", id, no, orig)
			}},
	}
	for _, tc := range tamper {
		tc.do()
		rep := r.verifyReport(t)
		if rep.OK || checkOK(t, rep, "versions") {
			t.Fatalf("verify passed with %s", tc.name)
		}
		tc.undo()
	}
	if rep := r.verifyReport(t); !rep.OK {
		t.Fatal("verify failed after undoing the tampering")
	}

	if _, err := r.db[schema.Audit].Querier().Exec(ctx, "DELETE FROM audit_records WHERE action = 'migration.import'"); err != nil {
		t.Fatal(err)
	}
	if rep := r.verifyReport(t); checkOK(t, rep, "versions") {
		t.Fatal("verify passed without the import's version-sample record")
	}
}

func TestImportRefusesAnOlderVersionThatDoesNotMatchItsSample(t *testing.T) {
	r := newRig(t)
	for i, s := range r.bundle.Manifest.Samples {
		if s.Version > 0 {
			r.bundle.Manifest.Samples[i].HMAC = strings.Repeat("0", len(s.HMAC))
			break
		}
	}
	if _, err := r.importIt(t, r.cfg()); code(err) != codes.BundleDamaged {
		t.Fatalf("err = %v, want BundleDamaged", err)
	}
	var n int
	if err := r.db[schema.Vault].Querier().QueryRow(context.Background(), "SELECT count(*) FROM secret_versions").Scan(&n); err != nil || n != 0 {
		t.Fatalf("secret_versions has %d rows (%v) after a refused import", n, err)
	}
}

// assertNoValues checks the import report carries no secret value, TOTP
// secret or password hash from the bundle.
func assertNoValues(t *testing.T, b *bundle.Bundle, rep any) {
	t.Helper()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	if r, ok := rep.(interface{ Text(io.Writer) error }); ok {
		if err := r.Text(&text); err != nil {
			t.Fatal(err)
		}
	}
	out := string(raw) + text.String()
	var values []string
	for _, stream := range []string{"vault.secret_records", "vault.secret_versions"} {
		_ = b.Each(stream, func(line []byte) error {
			var row struct {
				Fields map[string]string `json:"fields"`
			}
			_ = json.Unmarshal(line, &row)
			for _, v := range row.Fields {
				if len(v) >= 8 {
					values = append(values, v)
				}
			}
			return nil
		})
	}
	_ = b.Each("identity.user_totp", func(line []byte) error {
		var row struct {
			Secret string `json:"secret"`
		}
		_ = json.Unmarshal(line, &row)
		values = append(values, row.Secret)
		return nil
	})
	_ = b.Each(schema.KratosStream, func(line []byte) error {
		var id kratos.Identity
		_ = json.Unmarshal(line, &id)
		if h := id.PasswordHash(); h != "" {
			values = append(values, h)
		}
		return nil
	})
	if len(values) == 0 {
		t.Fatal("no values collected; the check would prove nothing")
	}
	for _, v := range values {
		if strings.Contains(out, v) {
			t.Fatal("the report carries a value from the bundle")
		}
	}
}

// assertSecurityReview checks the import lists every security setting with
// its new default and warns that tokens lose the synthetic SSH private keys,
// which the source marks super-sensitive and stores with API access off.
func assertSecurityReview(t *testing.T, rep *report.Import) {
	t.Helper()
	if len(rep.Security.Settings) != 8 {
		t.Fatalf("security settings: %+v", rep.Security.Settings)
	}
	var api string
	for _, w := range rep.Security.Warnings {
		if strings.HasPrefix(w, "API access to super-sensitive fields: off") {
			api = w
		}
	}
	if api == "" {
		t.Fatalf("no API access warning in %q", rep.Security.Warnings)
	}
	var text strings.Builder
	if err := rep.Text(&text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"security settings (imported / new default):", "API access to super-sensitive fields", "warning: " + api} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("the text report lacks %q", want)
		}
	}
}

// The appliance migration: current values only, every sign-in reset, the
// owner's mapping applied, and parity checked on the way in.
func TestImportAppliesTheMappingWithParity(t *testing.T) {
	r := newRigWith(t, func(c *source.Config) { c.CurrentOnly, c.ResetSignIn = true, true })
	p := mustPlan(`{
	  "format": "sneakers-migrate-mapping", "version": 1, "unlisted": "keep",
	  "folders": [{"from": "Infrastructure/Linux", "to": "Servers/Linux"}],
	  "secrets": [
	    {"id": "sec-0021", "from": {"folder": "Databases/Production"}, "to": {"folder": "Servers/Unsorted", "name": "renamed by the mapping"}},
	    {"id": "sec-0026", "from": {}, "drop": true}
	  ]
	}`)
	cfg := r.cfg()
	cfg.Plan = p
	out, err := r.importIt(t, cfg)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	rep := out.Report
	if rep.Remap == nil || rep.Remap.SecretsDropped != 1 || rep.Remap.SecretsMoved != 1 || rep.Remap.FoldersCreated != 2 || rep.Remap.FoldersMoved != 1 {
		t.Fatalf("remap = %+v", rep.Remap)
	}
	par := map[string]report.Parity{}
	for _, c := range rep.Parity {
		par[c.Name] = c
		if c.Expected != c.Target || !c.OK {
			t.Fatalf("parity %s = %+v", c.Name, c)
		}
	}
	sec, _ := r.bundle.Manifest.Table("vault.secrets")
	fol, _ := r.bundle.Manifest.Table("vault.folders")
	if par["secrets"].Source != sec.Rows || par["secrets"].Dropped != 1 || par["secrets"].Expected != sec.Rows-1 ||
		par["folders"].Created != 2 || par["folders"].Expected != fol.Rows+2 || len(par) != 6 {
		t.Fatalf("parity = %+v", rep.Parity)
	}
	var text strings.Builder
	if err := rep.Text(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "parity (source / dropped / created / expected / target):") {
		t.Fatalf("the text report has no parity table:\n%s", text.String())
	}

	ctx := context.Background()
	var totp, passkeys, versions, secrets int
	_ = r.db[schema.Identity].Querier().QueryRow(ctx, "SELECT count(*) FROM user_totp").Scan(&totp)
	_ = r.db[schema.Identity].Querier().QueryRow(ctx, "SELECT count(*) FROM user_webauthn_credentials").Scan(&passkeys)
	_ = r.db[schema.Vault].Querier().QueryRow(ctx, "SELECT count(*) FROM secret_versions").Scan(&versions)
	_ = r.db[schema.Vault].Querier().QueryRow(ctx, "SELECT count(*) FROM secrets").Scan(&secrets)
	if totp != 0 || passkeys != 0 || versions != secrets {
		t.Fatalf("totp %d, passkeys %d, versions %d for %d secrets", totp, passkeys, versions, secrets)
	}
	ids, err := kratos.New(r.kratos.URL).List(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id.PasswordHash() != "" || r.kratos.Passwords[id.ID] != "" {
			t.Fatal("an imported identity has a password after a sign-in reset")
		}
	}
	var name, folder string
	if err := r.db[schema.Vault].Querier().QueryRow(ctx, "SELECT data->>'name', data->>'folderId' FROM secrets WHERE id = 'sec-0021'").Scan(&name, &folder); err != nil || name != "renamed by the mapping" || !strings.HasPrefix(folder, "folder-mig-") {
		t.Fatalf("sec-0021 = %q in %q (%v)", name, folder, err)
	}
	var hash string
	if err := r.db[schema.Audit].Querier().QueryRow(ctx, "SELECT attributes->>'mapping_sha256' FROM audit_records WHERE action = 'migration.import'").Scan(&hash); err != nil || hash != p.SHA256 {
		t.Fatalf("audit summary mapping_sha256 = %q (%v)", hash, err)
	}

	rep2 := r.verifyWith(t, verify.Config{DSN: r.dsn, Plan: p})
	if !rep2.OK || !checkOK(t, rep2, "sign-in reset") || !checkOK(t, rep2, "parity") {
		t.Fatal("verify failed after a mapped import")
	}
	if rep3 := r.verifyWith(t, verify.Config{DSN: r.dsn, Plan: keepAll}); rep3.OK || checkOK(t, rep3, "mapping") {
		t.Fatal("verify passed with another mapping file than the import's")
	}

	// The first admin's way in: one account gets a one-time password.
	owner := r.cfg()
	owner.Plan, owner.Wipe, owner.OwnerEmail = p, true, "owner@example.org"
	again, err := r.importIt(t, owner)
	if err != nil {
		t.Fatalf("re-import with a wipe: %v", err)
	}
	if !again.Report.Wiped || len(again.OwnerPassword) != 24 {
		t.Fatalf("wiped %v, owner password length %d", again.Report.Wiped, len(again.OwnerPassword))
	}
	if !r.verifyWith(t, verify.Config{DSN: r.dsn, Plan: p}).OK {
		t.Fatal("verify failed after a re-import")
	}
}

func TestImportRefusesWithoutAMapping(t *testing.T) {
	r := newRig(t)
	cfg := r.cfg()
	cfg.Plan = nil
	_, err := r.importIt(t, cfg)
	if code(err) != codes.ModeRefused || !strings.Contains(err.Error(), "mapping") {
		t.Fatalf("err = %v, want ModeRefused naming the mapping file", err)
	}
	bad := r.cfg()
	bad.Plan = mustPlan(`{"format": "sneakers-migrate-mapping", "version": 1, "unlisted": "refuse"}`)
	if _, err := r.importIt(t, bad); code(err) != codes.MappingInvalid {
		t.Fatalf("err = %v, want MappingInvalid", err)
	}
	var n int
	if err := r.db[schema.Vault].Querier().QueryRow(context.Background(), "SELECT count(*) FROM secrets").Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused mapping wrote %d secrets (%v)", n, err)
	}
	owner := r.cfg()
	owner.OwnerEmail = "owner@example.org"
	if _, err := r.importIt(t, owner); code(err) != codes.ModeRefused {
		t.Fatalf("owner password without a sign-in reset: err = %v, want ModeRefused", err)
	}
}

func TestParityFailsLoudly(t *testing.T) {
	m := bundle.Manifest{Parity: []bundle.ParityCount{{Name: "secrets", Stream: "vault.secrets", Source: 5, Bundle: 5}}}
	m.Tables = []bundle.Table{{Name: "vault.secrets", Rows: 5}}
	got := target.CheckParity(m, map[string]int{"vault.secrets": 5}, map[string]int{"vault.secrets": 4}, &mapping.RemapStats{})
	for _, p := range got {
		if (p.Name == "secrets") == p.OK || (p.Name == "secrets" && p.Target != 4) {
			t.Fatalf("parity = %+v", got)
		}
	}
	err := target.ParityError(got)
	if code(err) != codes.ParityMismatch || !strings.Contains(err.Error(), "secrets") || !strings.Contains(err.Error(), "re-import") {
		t.Fatalf("err = %v", err)
	}
}

func TestSanitisedBundleImportsInRehearsalOnly(t *testing.T) {
	r := newRigWith(t, func(c *source.Config) { c.Sanitise = true })
	if _, err := r.importIt(t, r.cfg()); code(err) != codes.ModeRefused {
		t.Fatalf("sanitised bundle outside rehearsal: err = %v, want ModeRefused", err)
	}
	cfg := r.cfg()
	cfg.Rehearsal = true
	if _, err := r.importIt(t, cfg); err != nil {
		t.Fatalf("sanitised bundle in rehearsal: %v", err)
	}
	if !r.verifyIt(t) {
		t.Fatal("verify failed on a sanitised rehearsal import")
	}
}
