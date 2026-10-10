// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package source exports the original system: it reads each service database
// in one read-only snapshot, opens sealed values with the original key ring
// in memory, reads the Kratos identities with their password hashes, checks
// the audit chain, and builds the bundle. It never writes to the source.
package source

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/connect"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/envelope"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/totpcipher"
)

// Kratos is the part of the Kratos admin API export reads.
type Kratos interface {
	List(ctx context.Context, withPassword bool) ([]kratos.Identity, error)
	Version(ctx context.Context) (string, error)
}

// Config is what export needs. The keys are the source's own, held in memory
// only.
type Config struct {
	DSN       map[schema.Service]string
	RootKey   []byte
	DevSeed   string
	TOTP      *totpcipher.Cipher
	Samples   []string // designated test secrets; empty: pick SampleCount
	SampleMax int
	// CurrentOnly carries each secret's current version only.
	CurrentOnly bool
	// ResetSignIn leaves every password hash, TOTP seed and passkey behind:
	// users set a new password and enrol a second factor on the target.
	ResetSignIn bool
	// Sanitise keeps the shape and replaces every secret value, token hash
	// and target address with a generated fake, for a lab dry run. It
	// implies ResetSignIn.
	Sanitise bool
}

// Export reads the source and returns the bundle.
func Export(ctx context.Context, cfg Config, kr Kratos, lg log.Logger) (*bundle.Bundle, error) {
	start := time.Now()
	b := bundle.New(schema.SourceProfile.Name)
	if cfg.Sanitise {
		cfg.ResetSignIn = true
	}
	b.Manifest.CurrentOnly, b.Manifest.SignInReset, b.Manifest.Sanitised = cfg.CurrentOnly, cfg.ResetSignIn, cfg.Sanitise
	lg.Info("export started", log.F("bundle_id", b.Manifest.BundleID), log.F("profile", schema.SourceProfile.Name),
		log.F("current_only", cfg.CurrentOnly), log.F("reset_sign_in", cfg.ResetSignIn))
	x := &exporter{cfg: cfg, b: b, lg: lg, raw: map[string][][]byte{}, counted: map[string]int{}}
	for _, s := range schema.Services {
		if err := x.service(ctx, s); err != nil {
			return nil, err
		}
	}
	if err := x.kratos(ctx, kr); err != nil {
		return nil, err
	}
	if err := x.auditHead(); err != nil {
		return nil, err
	}
	if err := x.samples(); err != nil {
		return nil, err
	}
	if err := x.parity(); err != nil {
		return nil, err
	}
	b.Manifest.NotCarried = append(b.Manifest.NotCarried, bundle.NotCarried{
		Name: "identity.lldap_group_sync", Rows: 0,
		Reason: "lldap group-sync state; this source version keeps none (removed by its identity migration 8)",
	})
	if err := b.Seal(); err != nil {
		return nil, err
	}
	lg.Info("export finished", log.F("bundle_id", b.Manifest.BundleID), log.F("tables", len(b.Manifest.Tables)), log.F("elapsed_ms", time.Since(start).Milliseconds()))
	return b, nil
}

type exporter struct {
	cfg  Config
	b    *bundle.Bundle
	lg   log.Logger
	ring *envelope.Keyring
	raw  map[string][][]byte
	// sealedOpen counts opened records per key ref, for the log.
	refs map[string]int
	// counted is each parity category's count(*) in the source snapshot.
	counted map[string]int
}

func (x *exporter) service(ctx context.Context, s schema.Service) error {
	dsn := x.cfg.DSN[s]
	if dsn == "" {
		return fmt.Errorf("no DSN for the %s database", s)
	}
	db, err := connect.Postgres(ctx, "the source "+string(s)+" database", dsn, x.lg)
	if err != nil {
		return fmt.Errorf("connect to the %s database: %w", s, err)
	}
	defer db.Close()
	return db.RunInTx(ctx, func(tx postgres.Tx) error {
		// One consistent, read-only snapshot per database.
		if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil {
			return err
		}
		if err := checkVersion(ctx, tx, s); err != nil {
			return err
		}
		if s == schema.Vault {
			if err := x.loadRing(ctx, tx); err != nil {
				return err
			}
		}
		for _, c := range schema.ParityCategories {
			if lt, ok := schema.Lookup(c.Stream); ok && lt.Service == s {
				var n int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+lt.Name).Scan(&n); err != nil { // #nosec G202 -- names come from the fixed table list
					return fmt.Errorf("count %s: %w", c.Stream, err)
				}
				x.counted[c.Stream] = n
			}
		}
		for _, t := range schema.Of(s) {
			rows, err := readTable(ctx, tx, t)
			if err != nil {
				return err
			}
			x.raw[t.Stream()] = rows
			if left := x.leaveBehind(t, rows); left != nil {
				x.b.Stream(t.Stream())
				x.b.Manifest.NotCarried = append(x.b.Manifest.NotCarried, *left)
				x.lg.Info("rows left behind", log.F("table", t.Stream()), log.F("rows", left.Rows), log.F("reason", left.Reason))
				continue
			}
			if t.Stream() == "vault.secret_versions" && x.cfg.CurrentOnly {
				var older int
				rows, older = currentVersions(rows)
				x.b.Manifest.NotCarried = append(x.b.Manifest.NotCarried, bundle.NotCarried{Name: "vault.secret_versions.history", Rows: older,
					Reason: "older and staged versions; each secret carries its current value only"})
				x.lg.Info("secret history left behind", log.F("versions", older))
			}
			if !t.Carried() {
				reason := "transient (pending codes or ceremony state)"
				if t.Kind == schema.Replaced {
					reason = "the source key ring; the target vault keeps its own and every value is re-sealed under it"
				}
				x.b.Manifest.NotCarried = append(x.b.Manifest.NotCarried, bundle.NotCarried{Name: t.Stream(), Rows: len(rows), Reason: reason})
				x.lg.Debug("table left behind", log.F("table", t.Stream()), log.F("rows", len(rows)))
				continue
			}
			if err := x.write(t, rows); err != nil {
				return err
			}
			x.lg.Debug("table exported", log.F("table", t.Stream()), log.F("rows", len(rows)))
		}
		return nil
	})
}

// checkVersion refuses a database that isn't at the source profile's version.
func checkVersion(ctx context.Context, q postgres.Querier, s schema.Service) error {
	var version int64
	var dirty bool
	query := "SELECT version, dirty FROM public." + schema.VersionTable(s) // #nosec G202 -- a fixed table name
	if err := q.QueryRow(ctx, query).Scan(&version, &dirty); err != nil {
		return codes.Wrap(codes.SourceVersion, fmt.Errorf("the %s database has no readable migration version: %w", s, err))
	}
	want := schema.SourceProfile.Versions[s]
	if dirty || version != want {
		return codes.Wrap(codes.SourceVersion, fmt.Errorf("the %s database is at migration %d (dirty %t); this tool reads %d (%s)", s, version, dirty, want, schema.SourceProfile.Name))
	}
	return nil
}

func readTable(ctx context.Context, q postgres.Querier, t schema.Table) ([][]byte, error) {
	sql := fmt.Sprintf("SELECT row_to_json(t)::text FROM public.%s t ORDER BY %s", t.Name, strings.Join(t.Key, ", ")) // #nosec G201 -- names come from the fixed table list
	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", t.Stream(), err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, []byte(s))
	}
	return out, rows.Err()
}

func (x *exporter) loadRing(ctx context.Context, q postgres.Querier) error {
	rows, err := q.Query(ctx, "SELECT ref, wrapped_key, root_ref, active FROM public.kek_keyring ORDER BY ref")
	if err != nil {
		return fmt.Errorf("read the key ring: %w", err)
	}
	defer rows.Close()
	var ring []envelope.KeyringRow
	for rows.Next() {
		var r envelope.KeyringRow
		if err := rows.Scan(&r.Ref, &r.WrappedKey, &r.RootRef, &r.Active); err != nil {
			return err
		}
		ring = append(ring, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	x.ring, err = envelope.LoadKeyring(ring, x.cfg.RootKey, x.cfg.DevSeed)
	if err != nil {
		return codes.Wrap(codes.SourceValue, err)
	}
	x.refs = map[string]int{}
	x.lg.Info("source key ring opened", log.F("generations", len(ring)), log.F("dev_static_loaded", x.cfg.DevSeed != ""))
	return nil
}

func (x *exporter) write(t schema.Table, rows [][]byte) error {
	s := x.b.Stream(t.Stream())
	for _, raw := range rows {
		switch t.Stream() {
		case "vault.secret_records", "vault.secret_versions":
			out, err := x.openSealed(t, raw)
			if err != nil {
				return err
			}
			if err := s.Add(out); err != nil {
				return err
			}
		case "identity.user_totp":
			out, err := x.openTOTP(raw)
			if err != nil {
				return err
			}
			if err := s.Add(out); err != nil {
				return err
			}
		default:
			if x.cfg.Sanitise {
				var err error
				if raw, err = sanitiseRow(t.Stream(), raw); err != nil {
					return err
				}
			}
			if err := s.AddRaw(raw); err != nil {
				return err
			}
		}
	}
	return nil
}

// fake returns a random printable string as long as v, keeping line breaks
// so a multi-line value stays multi-line.
func fake(v string) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := []byte(v)
	r := make([]byte, len(b))
	_, _ = rand.Read(r)
	for i := range b {
		if b[i] != '\n' {
			b[i] = alphabet[int(r[i])%len(alphabet)]
		}
	}
	return string(b)
}

// sanitiseRow replaces the hashes and addresses a plain row carries.
func sanitiseRow(stream string, raw []byte) ([]byte, error) {
	var row map[string]any
	if err := bundle.Decode(raw, &row); err != nil {
		return nil, err
	}
	switch stream {
	case "identity.user_tokens", "identity.api_tokens":
		if h, ok := row["token_hash"].(string); ok {
			row["token_hash"] = fake(h)
		}
	case "vault.targets":
		if d, ok := row["data"].(map[string]any); ok {
			for _, k := range []string{"hostname", "address", "ip"} {
				if _, ok := d[k]; ok {
					d[k] = "t-" + strings.ToLower(fake("xxxxxxxx")) + ".sanitised.example.org"
				}
			}
		}
	default:
		return raw, nil
	}
	return json.Marshal(row)
}

// openSealed replaces the stored envelope with the opened fields.
func (x *exporter) openSealed(t schema.Table, raw []byte) (map[string]any, error) {
	var row map[string]any
	if err := bundle.Decode(raw, &row); err != nil {
		return nil, err
	}
	recRaw, err := json.Marshal(row["record"])
	if err != nil {
		return nil, err
	}
	var rec envelope.Record
	if err := json.Unmarshal(recRaw, &rec); err != nil {
		return nil, codes.Wrap(codes.SourceValue, fmt.Errorf("%s %s: not a sealed record", t.Stream(), rowID(row)))
	}
	fields, err := x.ring.Open(rec)
	if err != nil {
		return nil, codes.Wrap(codes.SourceValue, fmt.Errorf("%s %s (key %s): %w", t.Stream(), rowID(row), rec.KeyRef, err))
	}
	x.refs[rec.KeyRef]++
	if x.cfg.Sanitise {
		for k, v := range fields {
			fields[k] = fake(v)
		}
	}
	delete(row, "record")
	row["fields"] = fields
	return row, nil
}

func rowID(row map[string]any) string {
	id := fmt.Sprint(row["secret_id"])
	if v, ok := row["version_no"]; ok {
		id += "@v" + fmt.Sprint(v)
	}
	return id
}

func (x *exporter) openTOTP(raw []byte) (map[string]any, error) {
	var row map[string]any
	if err := bundle.Decode(raw, &row); err != nil {
		return nil, err
	}
	if x.cfg.TOTP == nil {
		return nil, codes.Wrap(codes.SourceValue, errors.New("the source has TOTP secrets but no TOTP key was given (SOURCE_TOTP_ENC_KEY)"))
	}
	sealed, _ := row["encrypted_secret"].(string)
	plain, err := x.cfg.TOTP.Open(sealed)
	if err != nil {
		return nil, codes.Wrap(codes.SourceValue, fmt.Errorf("identity.user_totp %v: %w", row["user_id"], err))
	}
	delete(row, "encrypted_secret")
	row["secret"] = plain
	return row, nil
}

func (x *exporter) kratos(ctx context.Context, kr Kratos) error {
	v, err := kr.Version(ctx)
	if err != nil {
		return fmt.Errorf("source Kratos: %w", err)
	}
	x.b.Manifest.SourceVersion["kratos"] = v
	ids, err := kr.List(ctx, !x.cfg.ResetSignIn)
	if err != nil {
		return fmt.Errorf("source Kratos: %w", err)
	}
	s := x.b.Stream(schema.KratosStream)
	if x.cfg.ResetSignIn {
		for _, id := range ids {
			id.Credentials = nil
			if err := s.Add(id); err != nil {
				return err
			}
		}
		x.b.Manifest.NotCarried = append(x.b.Manifest.NotCarried, bundle.NotCarried{Name: "kratos.credentials.password", Rows: len(ids),
			Reason: "sign-in reset: no identity carries a password; every user sets a new one on the target"})
		x.lg.Info("source Kratos exported without credentials", log.F("identities", len(ids)), log.F("kratos_version", v))
		for s, ver := range schema.SourceProfile.Versions {
			x.b.Manifest.SourceVersion[string(s)] = strconv.FormatInt(ver, 10)
		}
		return nil
	}
	other := map[string]int{}
	for _, id := range ids {
		for typ := range id.Credentials {
			if typ != "password" {
				other[typ]++
			}
		}
		if err := s.Add(id); err != nil {
			return err
		}
	}
	types := make([]string, 0, len(other))
	for t := range other {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		x.b.Manifest.NotCarried = append(x.b.Manifest.NotCarried, bundle.NotCarried{
			Name: "kratos.credentials." + t, Rows: other[t],
			Reason: "Kratos imports only password hashes; second factors live in the identity service",
		})
	}
	x.lg.Info("source Kratos exported", log.F("identities", len(ids)), log.F("kratos_version", v))
	for s, ver := range schema.SourceProfile.Versions {
		x.b.Manifest.SourceVersion[string(s)] = strconv.FormatInt(ver, 10)
	}
	return nil
}

// auditHead checks the source chain from genesis and records its head. A
// chain that doesn't verify here can't verify on the target, so export stops.
func (x *exporter) auditHead() error {
	rows := x.raw["audit.audit_records"]
	recs := make([]chain.Record, 0, len(rows))
	for _, raw := range rows {
		var r chain.Record
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("audit record: %w", err)
		}
		recs = append(recs, r)
	}
	if ok, at := chain.Verify(recs); !ok {
		return codes.Wrap(codes.SourceChain, fmt.Errorf("the source audit chain breaks at seq %d", at))
	}
	if n := len(recs); n > 0 {
		x.b.Manifest.AuditHead = bundle.Head{Seq: recs[n-1].Seq, Hash: recs[n-1].Hash}
	}
	x.lg.Info("source audit chain verified", log.F("records", len(recs)), log.F("head_seq", x.b.Manifest.AuditHead.Seq))
	x.lg.Info("source values opened", log.F("by_key_ref", fmt.Sprint(x.refs)))
	return nil
}

// samples records an HMAC of each sensitive value of the designated secrets,
// current and every version, under a fresh per-bundle key.
func (x *exporter) samples() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	x.b.Manifest.SampleKey = key
	sensitive, err := sensitiveFields(x.raw["vault.secret_types"])
	if err != nil {
		return err
	}
	type secret struct {
		ID   string `json:"id"`
		Data struct {
			TypeID   string `json:"typeId"`
			FolderID string `json:"folderId"`
			Retired  bool   `json:"retired"`
		} `json:"data"`
	}
	personal, err := personalFolders(x.raw["vault.folders"])
	if err != nil {
		return err
	}
	eligible := map[string]string{}
	var ids []string
	for _, raw := range x.raw["vault.secrets"] {
		var s secret
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		if s.Data.Retired || personal[s.Data.FolderID] || len(sensitive[s.Data.TypeID]) == 0 {
			continue
		}
		eligible[s.ID] = s.Data.TypeID
		ids = append(ids, s.ID)
	}
	chosen := x.cfg.Samples
	if len(chosen) == 0 {
		chosen = spread(ids, x.cfg.SampleMax)
	}
	want := map[string]bool{}
	for _, id := range chosen {
		if _, ok := eligible[id]; !ok {
			return fmt.Errorf("sample secret %s is not an active shared secret with a sensitive field", id)
		}
		want[id] = true
	}
	add := func(stream string, current bool) error {
		return x.b.Each(stream, func(raw []byte) error {
			var row struct {
				SecretID  string            `json:"secret_id"`
				VersionNo int               `json:"version_no"`
				Fields    map[string]string `json:"fields"`
			}
			if err := json.Unmarshal(raw, &row); err != nil {
				return err
			}
			if !want[row.SecretID] {
				return nil
			}
			for _, f := range sensitive[eligible[row.SecretID]] {
				v, ok := row.Fields[f]
				if !ok {
					continue
				}
				version := row.VersionNo
				if current {
					version = 0
				}
				x.b.Manifest.Samples = append(x.b.Manifest.Samples, bundle.Sample{SecretID: row.SecretID, Version: version, Field: f, HMAC: SampleHMAC(key, row.SecretID, version, f, v)})
			}
			return nil
		})
	}
	if err := add("vault.secret_records", true); err != nil {
		return err
	}
	if err := add("vault.secret_versions", false); err != nil {
		return err
	}
	x.lg.Info("sample reveals recorded", log.F("secrets", len(chosen)), log.F("values", len(x.b.Manifest.Samples)))
	return nil
}

// SampleHMAC is the keyed hash verify compares a revealed value against.
func SampleHMAC(key []byte, secretID string, version int, field, value string) string {
	m := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(m, "%s\x00%d\x00%s\x00", secretID, version, field)
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))
}

// sensitiveFields maps each secret type to the fields the vault reveals as
// sensitive (password kind or the sensitive flag).
func sensitiveFields(types [][]byte) (map[string][]string, error) {
	out := map[string][]string{}
	for _, raw := range types {
		var row struct {
			ID   string `json:"id"`
			Data struct {
				Fields []struct {
					Key       string `json:"key"`
					Kind      string `json:"kind"`
					Sensitive bool   `json:"sensitive"`
				} `json:"fields"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, err
		}
		for _, f := range row.Data.Fields {
			if f.Kind == "FIELD_KIND_PASSWORD" || f.Sensitive {
				out[row.ID] = append(out[row.ID], f.Key)
			}
		}
	}
	return out, nil
}

// personalFolders lists the folders in personal scope: verify reveals as a
// site administrator, who can't read other people's personal folders.
func personalFolders(folders [][]byte) (map[string]bool, error) {
	out := map[string]bool{}
	for _, raw := range folders {
		var row struct {
			ID   string `json:"id"`
			Data struct {
				Scope string `json:"scope"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, err
		}
		if row.Data.Scope == "FOLDER_SCOPE_PERSONAL" {
			out[row.ID] = true
		}
	}
	return out, nil
}

// spread picks up to n ids evenly across the sorted list.
func spread(ids []string, n int) []string {
	sort.Strings(ids)
	if n <= 0 || len(ids) <= n {
		return ids
	}
	out := make([]string, 0, n)
	step := float64(len(ids)) / float64(n)
	for i := 0; i < n; i++ {
		out = append(out, ids[int(float64(i)*step)])
	}
	return out
}

// leaveBehind says why a carried table's rows stay in the source, or nil.
func (x *exporter) leaveBehind(t schema.Table, rows [][]byte) *bundle.NotCarried {
	if !x.cfg.ResetSignIn {
		return nil
	}
	switch t.Stream() {
	case "identity.user_totp":
		return &bundle.NotCarried{Name: t.Stream(), Rows: len(rows), Reason: "sign-in reset: every user enrols a second factor again"}
	case "identity.user_webauthn_credentials":
		return &bundle.NotCarried{Name: t.Stream(), Rows: len(rows), Reason: "sign-in reset: every user registers their passkeys again"}
	}
	return nil
}

// currentVersions keeps each secret's active version (its newest unstaged
// one when none is marked active) and returns how many it left out.
func currentVersions(rows [][]byte) ([][]byte, int) {
	type ver struct {
		SecretID  string `json:"secret_id"`
		VersionNo int    `json:"version_no"`
		Active    bool   `json:"active"`
		Staged    bool   `json:"staged"`
	}
	best := map[string]int{}
	parsed := make([]ver, len(rows))
	for i, raw := range rows {
		_ = json.Unmarshal(raw, &parsed[i])
		v := parsed[i]
		if v.Staged {
			continue
		}
		j, ok := best[v.SecretID]
		switch {
		case !ok:
			best[v.SecretID] = i
		case v.Active && !parsed[j].Active:
			best[v.SecretID] = i
		case v.Active == parsed[j].Active && v.VersionNo > parsed[j].VersionNo:
			best[v.SecretID] = i
		}
	}
	keep := map[int]bool{}
	for _, i := range best {
		keep[i] = true
	}
	out := make([][]byte, 0, len(best))
	for i, raw := range rows {
		if keep[i] {
			out = append(out, raw)
		}
	}
	return out, len(rows) - len(out)
}

// parity records each category's source count next to the bundle's and
// stops when they differ.
func (x *exporter) parity() error {
	var bad []string
	for _, c := range schema.ParityCategories {
		rows := x.b.Stream(c.Stream).Rows()
		p := bundle.ParityCount{Name: c.Name, Stream: c.Stream, Source: x.counted[c.Stream], Bundle: rows}
		x.b.Manifest.Parity = append(x.b.Manifest.Parity, p)
		if p.Source != p.Bundle {
			bad = append(bad, fmt.Sprintf("%s: source %d, bundle %d", c.Name, p.Source, p.Bundle))
		}
	}
	if len(bad) > 0 {
		return codes.Wrap(codes.ParityMismatch, fmt.Errorf("export parity failed: %s", strings.Join(bad, "; ")))
	}
	x.lg.Info("export parity matches the source", log.F("categories", len(x.b.Manifest.Parity)))
	return nil
}
