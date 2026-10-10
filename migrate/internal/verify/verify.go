// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package verify checks a target against the bundle it was imported from:
// per-table counts, the audit chain from genesis to head, sample reveals of
// current values matched by keyed hash (never printed), every secret's older
// versions by number, timestamp and sealed fields (never revealed), and that
// every target resolves to a connection and its secrets, the dry run of a
// connection test. Any mismatch fails the run.
package verify

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/chain"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/connect"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/envelope"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/rpc"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/source"
)

// VaultReader is what verify reads from the target vault.
type VaultReader interface {
	Reveal(ctx context.Context, secretID string, field string) (string, error)
	Targets(ctx context.Context) ([]rpc.Target, error)
	Connections(ctx context.Context) ([]rpc.Connection, error)
	SecretExists(ctx context.Context, id string) (bool, error)
}

// ChainVerifier is the target audit service's chain check.
type ChainVerifier interface {
	VerifyChain(ctx context.Context) (valid bool, brokenAt, length uint64, err error)
}

// KratosLister lists the target's identities.
type KratosLister interface {
	List(ctx context.Context, withPassword bool) ([]kratos.Identity, error)
}

// Config is what verify needs.
type Config struct {
	DSN map[schema.Service]string
	Now func() time.Time
	// Plan is the mapping file the import applied; nil if it had none.
	Plan *mapping.Plan
}

// Run verifies the target and returns the report. An error means verify could
// not run; a mismatch is a report with OK false.
func Run(ctx context.Context, cfg Config, b *bundle.Bundle, v VaultReader, a ChainVerifier, kr KratosLister, lg log.Logger) (*report.Verify, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	rep := &report.Verify{BundleID: b.Manifest.BundleID, At: cfg.Now().UTC().Format(time.RFC3339)}
	dbs := map[schema.Service]*postgres.DB{}
	defer func() {
		for _, db := range dbs {
			db.Close()
		}
	}()
	for _, s := range schema.Services {
		db, err := connect.Postgres(ctx, "the target "+string(s)+" database", cfg.DSN[s], lg)
		if err != nil {
			return nil, fmt.Errorf("connect to the target %s database: %w", s, err)
		}
		dbs[s] = db
	}
	m, err := mapping.Map(b, mapping.Context{Now: time.Now(), Actor: "system:sneakers-migrate", Plan: cfg.Plan})
	if err != nil {
		return nil, err
	}
	if err := mappingApplied(ctx, rep, b, cfg.Plan, dbs[schema.Audit].Querier()); err != nil {
		return nil, err
	}
	at, err := importedAt(ctx, dbs[schema.Audit].Querier(), b.Manifest.BundleID)
	if err != nil {
		return nil, err
	}
	if err := counts(ctx, rep, b, m, dbs, kr, at); err != nil {
		return nil, err
	}
	if err := signIn(ctx, rep, b, dbs[schema.Identity].Querier(), kr, at); err != nil {
		return nil, err
	}
	if err := tokens(ctx, rep, m, dbs[schema.Identity].Querier()); err != nil {
		return nil, err
	}
	if err := auditChain(ctx, rep, b, dbs[schema.Audit].Querier(), a); err != nil {
		return nil, err
	}
	samples(ctx, rep, b, v)
	if err := versions(ctx, rep, b, m, dbs[schema.Vault].Querier(), dbs[schema.Audit].Querier()); err != nil {
		return nil, err
	}
	if err := targets(ctx, rep, b, v); err != nil {
		return nil, err
	}
	rep.Finish()
	lg.Info("verify finished", log.F("bundle_id", b.Manifest.BundleID), log.F("ok", rep.OK), log.F("failures", len(rep.Failures)))
	return rep, nil
}

func count(ctx context.Context, q postgres.Querier, sql string, args ...any) (int, error) {
	var n int
	err := q.QueryRow(ctx, sql, args...).Scan(&n)
	return n, err
}

// factorTables hold second factors a user enrols. One made after the import
// didn't come across, so counts and the sign-in reset check leave it out.
var factorTables = map[string]bool{"identity.user_totp": true, "identity.user_webauthn_credentials": true}

// importedAt is when this bundle's latest import finished (its audit
// summary), or nil if the target records none.
func importedAt(ctx context.Context, aq postgres.Querier, bundleID string) (*time.Time, error) {
	var occurred string
	err := aq.QueryRow(ctx, "SELECT occurred_at FROM public.audit_records WHERE action = 'migration.import' AND attributes->>'bundle_id' = $1 ORDER BY seq DESC LIMIT 1", bundleID).Scan(&occurred)
	if errors.Is(err, postgres.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the import's audit summary: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, occurred)
	if err != nil {
		return nil, fmt.Errorf("the import's audit summary: occurred_at %q: %w", occurred, err)
	}
	return &at, nil
}

func counts(ctx context.Context, rep *report.Verify, b *bundle.Bundle, m *mapping.Result, dbs map[schema.Service]*postgres.DB, kr KratosLister, at *time.Time) error {
	want := m.Expected()
	var bad []string
	for _, t := range schema.Tables {
		if !t.Carried() {
			continue
		}
		q := dbs[t.Service].Querier()
		sql := "SELECT count(*) FROM public." + t.Name // #nosec G202 -- names come from the fixed table list
		var args []any
		if t.Stream() == "audit.audit_records" {
			sql += " WHERE seq <= $1"
			args = append(args, int64(b.Manifest.AuditHead.Seq)) // #nosec G115 -- audit seq fits in bigint
		}
		if factorTables[t.Stream()] && at != nil {
			sql += " WHERE created_at <= $1"
			args = append(args, *at)
		}
		n, err := count(ctx, q, sql, args...)
		if err != nil {
			return fmt.Errorf("count %s: %w", t.Stream(), err)
		}
		bt, _ := b.Manifest.Table(t.Stream())
		rep.Counts = append(rep.Counts, report.Count{Table: t.Stream(), Bundle: bt.Rows, Expected: want[t.Stream()], Target: n})
		if n != want[t.Stream()] {
			bad = append(bad, fmt.Sprintf("%s %d, want %d", t.Stream(), n, want[t.Stream()]))
		}
	}
	ids, err := kr.List(ctx, false)
	if err != nil {
		return fmt.Errorf("target Kratos: %w", err)
	}
	kt, _ := b.Manifest.Table(schema.KratosStream)
	rep.Counts = append(rep.Counts, report.Count{Table: schema.KratosStream, Bundle: kt.Rows, Expected: kt.Rows, Target: len(ids)})
	if len(ids) != kt.Rows {
		bad = append(bad, fmt.Sprintf("%s %d, want %d", schema.KratosStream, len(ids), kt.Rows))
	}
	detail := fmt.Sprintf("%d tables and the Kratos identities match the manifest", len(rep.Counts)-1)
	if len(bad) > 0 {
		detail = strings.Join(bad, "; ")
		rep.Failures = append(rep.Failures, bad...)
	}
	rep.Add("counts", len(bad) == 0, detail)

	got := map[string]int{}
	for _, c := range rep.Counts {
		got[c.Table] = c.Target
	}
	rep.Parity = parity(b.Manifest, want, got, m.Remap)
	var pbad []string
	for _, p := range rep.Parity {
		if !p.OK {
			pbad = append(pbad, fmt.Sprintf("%s: source %d, dropped %d, created %d, expected %d, target %d", p.Name, p.Source, p.Dropped, p.Created, p.Expected, p.Target))
		}
	}
	pdetail := fmt.Sprintf("%d categories: the source, less what the mapping dropped, is what the target holds", len(rep.Parity))
	if len(pbad) > 0 {
		pdetail = strings.Join(pbad, "; ")
		rep.Failures = append(rep.Failures, pbad...)
	}
	rep.Add("parity", len(pbad) == 0, pdetail)
	return nil
}

// parity mirrors the import's parity table.
func parity(m bundle.Manifest, expected, target map[string]int, remap *mapping.RemapStats) []report.Parity {
	src := map[string]int{}
	for _, p := range m.Parity {
		src[p.Stream] = p.Source
	}
	var out []report.Parity
	for _, c := range schema.ParityCategories {
		bt, _ := m.Table(c.Stream)
		p := report.Parity{Name: c.Name, Source: bt.Rows, Bundle: bt.Rows, Expected: expected[c.Stream], Target: target[c.Stream]}
		if n, ok := src[c.Stream]; ok {
			p.Source = n
		}
		if remap != nil {
			switch c.Name {
			case "secrets":
				p.Dropped = remap.SecretsDropped
			case "folders":
				p.Dropped, p.Created = remap.FoldersDropped, remap.FoldersCreated
			}
		}
		p.OK = p.Source == p.Bundle && p.Bundle-p.Dropped+p.Created == p.Expected && p.Expected == p.Target
		out = append(out, p)
	}
	return out
}

// mappingApplied checks the import applied this mapping file: its hash is
// in the import's audit summary (or neither has one).
func mappingApplied(ctx context.Context, rep *report.Verify, b *bundle.Bundle, p *mapping.Plan, aq postgres.Querier) error {
	var recorded string
	err := aq.QueryRow(ctx, "SELECT coalesce(attributes->>'mapping_sha256', '') FROM public.audit_records WHERE action = 'migration.import' AND attributes->>'bundle_id' = $1 ORDER BY seq LIMIT 1", b.Manifest.BundleID).Scan(&recorded)
	if err != nil && !errors.Is(err, postgres.ErrNoRows) {
		return fmt.Errorf("read the import's audit summary: %w", err)
	}
	given := ""
	if p != nil {
		given = p.SHA256
	}
	ok := recorded == given
	detail := "no mapping file, as the import"
	switch {
	case !ok:
		detail = fmt.Sprintf("the import applied mapping %q, verify was given %q", recorded, given)
		rep.Failures = append(rep.Failures, "mapping: "+detail)
	case given != "":
		detail = "the import applied this mapping file (" + given + ")"
	}
	rep.Add("mapping", ok, detail)
	return nil
}

// signIn checks a sign-in reset held: no second factor and no password
// came across, apart from the one first-admin password import may set. A
// second factor enrolled after the import (a pending TOTP seed from opening
// the second-factor page included) is a user signing in, not a carried one.
func signIn(ctx context.Context, rep *report.Verify, b *bundle.Bundle, iq postgres.Querier, kr KratosLister, at *time.Time) error {
	if !b.Manifest.SignInReset {
		return nil
	}
	var totp, passkeys, since int
	if err := iq.QueryRow(ctx, `SELECT
	  (SELECT count(*) FROM public.user_totp WHERE $1::timestamptz IS NULL OR created_at <= $1),
	  (SELECT count(*) FROM public.user_webauthn_credentials WHERE $1::timestamptz IS NULL OR created_at <= $1),
	  (SELECT count(*) FROM public.user_totp WHERE created_at > $1) + (SELECT count(*) FROM public.user_webauthn_credentials WHERE created_at > $1)`, at).Scan(&totp, &passkeys, &since); err != nil {
		return fmt.Errorf("count second factors: %w", err)
	}
	ids, err := kr.List(ctx, true)
	if err != nil {
		return fmt.Errorf("target Kratos: %w", err)
	}
	withPassword := 0
	for _, id := range ids {
		if id.PasswordHash() != "" {
			withPassword++
		}
	}
	ok := totp == 0 && passkeys == 0 && withPassword <= 1
	detail := fmt.Sprintf("%d identities, %d with a password (at most the first admin's), no TOTP seed or passkey carried", len(ids), withPassword)
	if since > 0 {
		detail += fmt.Sprintf("; %d second factors enrolled since the import", since)
	}
	if !ok {
		detail = fmt.Sprintf("%d TOTP seeds, %d passkeys and %d passwords on the target after a sign-in reset", totp, passkeys, withPassword)
		rep.Failures = append(rep.Failures, "sign-in reset: "+detail)
	}
	rep.Add("sign-in reset", ok, detail)
	return nil
}

// tokens checks every active personal token from the bundle still
// authenticates on the target, by id: the same stored hash, not revoked or
// expired, and its user present, enabled and linked to a sign-in identity.
// The token itself is never needed or printed.
func tokens(ctx context.Context, rep *report.Verify, m *mapping.Result, iq postgres.Querier) error {
	users := map[string]mapping.Row{}
	for _, u := range m.Rows["identity.users"] {
		users[fmt.Sprint(u["id"])] = u
	}
	type target struct {
		hash, user string
		revoked    bool
		expires    *time.Time
	}
	have := map[string]target{}
	rows, err := iq.Query(ctx, "SELECT id, token_hash, user_id, revoked_at IS NOT NULL, expires_at FROM public.user_tokens")
	if err != nil {
		return fmt.Errorf("read the target personal tokens: %w", err)
	}
	for rows.Next() {
		var id string
		var t target
		if err := rows.Scan(&id, &t.hash, &t.user, &t.revoked, &t.expires); err != nil {
			rows.Close()
			return err
		}
		have[id] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	subjects := map[string]bool{}
	disabled := map[string]bool{}
	urows, err := iq.Query(ctx, "SELECT id, subject, disabled_at IS NOT NULL FROM public.users")
	if err != nil {
		return fmt.Errorf("read the target users: %w", err)
	}
	for urows.Next() {
		var id, subject string
		var off bool
		if err := urows.Scan(&id, &subject, &off); err != nil {
			urows.Close()
			return err
		}
		subjects[id], disabled[id] = subject != "", off
	}
	urows.Close()
	if err := urows.Err(); err != nil {
		return err
	}
	now := time.Now()
	var okN, skipped int
	var bad []string
	for _, t := range m.Rows["identity.user_tokens"] {
		id := fmt.Sprint(t["id"])
		if t["revoked_at"] != nil && fmt.Sprint(t["revoked_at"]) != "" {
			skipped++
			continue
		}
		if exp, err := time.Parse(time.RFC3339Nano, fmt.Sprint(t["expires_at"])); err == nil && exp.Before(now) {
			skipped++
			continue
		}
		g, found := have[id]
		user := fmt.Sprint(t["user_id"])
		switch {
		case !found:
			bad = append(bad, id+": missing from the target")
		case g.hash != fmt.Sprint(t["token_hash"]):
			bad = append(bad, id+": stored differently from the source")
		case g.revoked || (g.expires != nil && g.expires.Before(now)):
			bad = append(bad, id+": revoked or expired on the target")
		case disabled[user]:
			skipped++
		case !subjects[user]:
			bad = append(bad, id+": its user has no sign-in identity")
		default:
			okN++
		}
	}
	sort.Strings(bad)
	detail := fmt.Sprintf("%d active personal tokens authenticate (checked by id); %d skipped (revoked, expired or a disabled user)", okN, skipped)
	if len(bad) > 0 {
		detail = strings.Join(bad, "; ")
		rep.Failures = append(rep.Failures, bad...)
	}
	rep.Tokens = report.Tokens{OK: okN, Skipped: skipped, Failing: bad}
	rep.Add("personal tokens", len(bad) == 0, detail)
	return nil
}

// auditChain checks the chain twice: the audit service's own VerifyChain,
// and an independent walk of every stored record, plus that the imported
// head is the source's head.
func auditChain(ctx context.Context, rep *report.Verify, b *bundle.Bundle, q postgres.Querier, a ChainVerifier) error {
	valid, broken, length, err := a.VerifyChain(ctx)
	if err != nil {
		return fmt.Errorf("audit VerifyChain: %w", err)
	}
	recs, err := loadChain(ctx, q)
	if err != nil {
		return err
	}
	own, ownBroken := chain.Verify(recs)
	head := b.Manifest.AuditHead
	headOK := head.Seq == 0 || (uint64(len(recs)) >= head.Seq && recs[head.Seq-1].Hash == head.Hash)
	ok := valid && own && headOK
	var appended uint64
	if length > head.Seq {
		appended = length - head.Seq
	}
	detail := fmt.Sprintf("valid from genesis to head: %d records (source head seq %d matches; %d appended by the import)", length, head.Seq, appended)
	if !ok {
		detail = fmt.Sprintf("audit service valid=%t broken at %d; independent walk valid=%t broken at %d; source head matches=%t", valid, broken, own, ownBroken, headOK)
		rep.Failures = append(rep.Failures, "audit chain: "+detail)
	}
	rep.Add("audit chain", ok, detail)
	return nil
}

func loadChain(ctx context.Context, q postgres.Querier) ([]chain.Record, error) {
	rows, err := q.Query(ctx, "SELECT row_to_json(t)::text FROM public.audit_records t ORDER BY seq")
	if err != nil {
		return nil, fmt.Errorf("read the audit chain: %w", err)
	}
	defer rows.Close()
	var out []chain.Record
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		var r chain.Record
		if err := json.Unmarshal([]byte(s), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// samples reveals the current value of each sample and compares its keyed
// hash. Older-version samples were matched by the import before sealing.
func samples(ctx context.Context, rep *report.Verify, b *bundle.Bundle, v VaultReader) {
	var bad []string
	secrets := map[string]bool{}
	n := 0
	for _, s := range b.Manifest.Samples {
		if s.Version != 0 {
			continue
		}
		n++
		secrets[s.SecretID] = true
		got, err := v.Reveal(ctx, s.SecretID, s.Field)
		where := s.SecretID + "#" + s.Field
		if err != nil {
			bad = append(bad, where+": "+err.Error())
			continue
		}
		h := source.SampleHMAC(b.Manifest.SampleKey, s.SecretID, 0, s.Field, got)
		if !hmac.Equal([]byte(h), []byte(s.HMAC)) {
			bad = append(bad, where+": does not match the source")
		}
	}
	ok := n > 0 && len(bad) == 0
	detail := fmt.Sprintf("%d current values of %d test secrets match by keyed hash", n, len(secrets))
	if n == 0 {
		detail = "the bundle names no current sample values"
	}
	if len(bad) > 0 {
		detail = fmt.Sprintf("%d of %d values do not match", len(bad), n)
		rep.Failures = append(rep.Failures, bad...)
	}
	rep.Add("sample reveals", ok, detail)
}

type versionKey struct {
	secretID string
	no       int
}

type versionMeta struct {
	createdAt time.Time
	fields    []string
}

// versions compares every secret version in the target with the bundle
// without revealing it: the version numbers, each version's timestamp, and
// that each is sealed with the bundle's field names. It also reads the
// import's own record that every older-version sample matched before sealing.
func versions(ctx context.Context, rep *report.Verify, b *bundle.Bundle, m *mapping.Result, vq, aq postgres.Querier) error {
	want := map[versionKey]versionMeta{}
	for _, r := range m.Rows["vault.secret_versions"] {
		k, meta, err := bundleVersion(r)
		if err != nil {
			return err
		}
		want[k] = meta
	}
	got, err := targetVersions(ctx, vq)
	if err != nil {
		return err
	}
	var bad []string
	secrets := map[string]bool{}
	for k, w := range want {
		secrets[k.secretID] = true
		where := fmt.Sprintf("%s@v%d", k.secretID, k.no)
		g, ok := got[k]
		switch {
		case !ok:
			bad = append(bad, where+": missing from the target")
		case !g.createdAt.Equal(w.createdAt):
			bad = append(bad, where+": created_at differs from the source")
		case strings.Join(g.fields, ",") != strings.Join(w.fields, ","):
			bad = append(bad, fmt.Sprintf("%s: %d sealed fields, the source has %d", where, len(g.fields), len(w.fields)))
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			bad = append(bad, fmt.Sprintf("%s@v%d: not in the bundle", k.secretID, k.no))
		}
	}
	sort.Strings(bad)

	older := 0
	for _, s := range b.Manifest.Samples {
		if s.Version > 0 {
			older++
		}
	}
	var matched string
	err = aq.QueryRow(ctx, "SELECT coalesce(attributes->>'version_samples_matched', '') FROM public.audit_records WHERE action = 'migration.import' AND attributes->>'bundle_id' = $1 ORDER BY seq LIMIT 1", b.Manifest.BundleID).Scan(&matched)
	switch {
	case errors.Is(err, postgres.ErrNoRows):
		bad = append(bad, "older-version samples: the import's audit summary is missing")
	case err != nil:
		return fmt.Errorf("read the import's audit summary: %w", err)
	case matched != strconv.Itoa(older):
		bad = append(bad, fmt.Sprintf("older-version samples: the import matched %q of %d", matched, older))
	}

	detail := fmt.Sprintf("%d versions of %d secrets match the bundle by number, timestamp and sealed fields; %d older sample values matched before sealing", len(want), len(secrets), older)
	if len(bad) > 0 {
		detail = strings.Join(bad, "; ")
		rep.Failures = append(rep.Failures, bad...)
	}
	rep.Add("versions", len(bad) == 0, detail)
	return nil
}

func bundleVersion(r map[string]any) (versionKey, versionMeta, error) {
	id, _ := r["secret_id"].(string)
	no, err := strconv.Atoi(fmt.Sprint(r["version_no"]))
	if id == "" || err != nil {
		return versionKey{}, versionMeta{}, fmt.Errorf("vault.secret_versions: a row without secret_id or version_no")
	}
	k := versionKey{secretID: id, no: no}
	at, _ := r["created_at"].(string)
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return k, versionMeta{}, fmt.Errorf("vault.secret_versions %s@v%d: created_at: %w", id, k.no, err)
	}
	fm, _ := r["fields"].(map[string]any)
	names := make([]string, 0, len(fm))
	for f := range fm {
		names = append(names, f)
	}
	sort.Strings(names)
	return k, versionMeta{createdAt: t, fields: names}, nil
}

func targetVersions(ctx context.Context, q postgres.Querier) (map[versionKey]versionMeta, error) {
	rows, err := q.Query(ctx, "SELECT secret_id, version_no, created_at, record FROM public.secret_versions")
	if err != nil {
		return nil, fmt.Errorf("read the target secret versions: %w", err)
	}
	defer rows.Close()
	out := map[versionKey]versionMeta{}
	for rows.Next() {
		var k versionKey
		var meta versionMeta
		var raw []byte
		if err := rows.Scan(&k.secretID, &k.no, &meta.createdAt, &raw); err != nil {
			return nil, err
		}
		var rec envelope.Record
		if err := json.Unmarshal(raw, &rec); err == nil && len(rec.WrappedDEK) > 0 {
			for f := range rec.Fields {
				meta.fields = append(meta.fields, f)
			}
			sort.Strings(meta.fields)
		}
		out[k] = meta
	}
	return out, rows.Err()
}

func targets(ctx context.Context, rep *report.Verify, b *bundle.Bundle, v VaultReader) error {
	ts, err := v.Targets(ctx)
	if err != nil {
		return fmt.Errorf("vault ListTargets: %w", err)
	}
	cs, err := v.Connections(ctx)
	if err != nil {
		return fmt.Errorf("vault ListConnections: %w", err)
	}
	conns := map[string]rpc.Connection{}
	for _, c := range cs {
		conns[c.ID] = c
	}
	bt, _ := b.Manifest.Table("vault.targets")
	var bad, unpinned []string
	if len(ts) != bt.Rows {
		bad = append(bad, fmt.Sprintf("vault lists %d targets, the bundle has %d", len(ts), bt.Rows))
	}
	checked := map[string]bool{}
	for _, t := range ts {
		c, ok := conns[t.ConnectionID]
		switch {
		case t.Hostname == "":
			bad = append(bad, t.ID+": no host name")
		case !ok:
			bad = append(bad, t.ID+": connection "+t.ConnectionID+" does not resolve")
		default:
			if c.Protocol == "ssh" && !t.Pinned {
				unpinned = append(unpinned, t.ID)
			}
			if c.PrivilegedSecretID != "" && !checked[c.PrivilegedSecretID] {
				checked[c.PrivilegedSecretID] = true
				if exists, err := v.SecretExists(ctx, c.PrivilegedSecretID); err != nil || !exists {
					bad = append(bad, fmt.Sprintf("%s: connection %s privileged secret %s does not resolve", t.ID, c.ID, c.PrivilegedSecretID))
				}
			}
		}
	}
	sort.Strings(unpinned)
	detail := fmt.Sprintf("%d targets resolve to their connection and secrets; dry run only (egress is denied); %d SSH targets await host-key pins", len(ts), len(unpinned))
	if len(bad) > 0 {
		detail = strings.Join(bad, "; ")
		rep.Failures = append(rep.Failures, bad...)
	}
	rep.Add("targets (dry run)", len(bad) == 0, detail)
	return nil
}
