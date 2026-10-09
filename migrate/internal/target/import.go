// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package target imports a bundle into a fresh Sneakers-PAM install: Kratos
// identities through the admin API, every service database through its own
// baseline layout in one transaction per service, secret values re-sealed by
// the target vault, the audit chain inserted raw, then the migration's own
// audit entries appended through the audit service.
package target

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/rpc"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/settings"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/source"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/totpcipher"
)

// vaultWriteLock is the advisory lock key the vault takes around every state
// write. The import holds it for the vault transaction, so no vault replica
// persists a snapshot over the imported rows.
const vaultWriteLock int64 = 0x7661756c74

const insertChunk = 500

// Sealer re-seals field sets under the target vault's key.
type Sealer interface {
	Seal(ctx context.Context, items []map[string]string) ([][]byte, error)
}

// Recorder appends an audit event through the target audit service.
type Recorder interface {
	Record(ctx context.Context, e rpc.Event) error
}

// Kratos is the part of the target Kratos admin API import uses.
type Kratos interface {
	List(ctx context.Context, withPassword bool) ([]kratos.Identity, error)
	CreateFrom(ctx context.Context, src kratos.Identity) (string, error)
	FindByIdentifier(ctx context.Context, identifier string) (string, error)
	SetPassword(ctx context.Context, id, password string) error
	Delete(ctx context.Context, id string) error
}

// Deps are the target services.
type Deps struct {
	Sealer   Sealer
	Recorder Recorder
	Kratos   Kratos
}

// Config is what an import needs.
type Config struct {
	DSN map[schema.Service]string
	// TOTP is the target identity's TOTP key; needed when the bundle has TOTP
	// secrets.
	TOTP       *totpcipher.Cipher
	Rehearsal  bool
	Wipe       bool
	OwnerEmail string
	Actor      string
	Now        func() time.Time
	// Plan is the owner's approved mapping file; required outside rehearsal.
	Plan *mapping.Plan
}

// Outcome is the report plus the one value shown once: the owner's new
// password in rehearsal mode. It is never written to the report.
type Outcome struct {
	Report        *report.Import
	OwnerPassword string
}

// Import runs the import.
func Import(ctx context.Context, cfg Config, b *bundle.Bundle, d Deps, lg log.Logger) (*Outcome, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Actor == "" {
		cfg.Actor = "system:sneakers-migrate"
	}
	if err := checkMode(cfg, b); err != nil {
		return nil, err
	}
	mode := "cutover"
	if cfg.Rehearsal {
		mode = "rehearsal"
	}
	rep := &report.Import{BundleID: b.Manifest.BundleID, Mode: mode, StartedAt: cfg.Now().UTC().Format(time.RFC3339), Services: map[string]string{}, NotCarried: b.Manifest.NotCarried,
		CurrentOnly: b.Manifest.CurrentOnly, SignInReset: b.Manifest.SignInReset}
	lg.Info("import started", log.F("bundle_id", b.Manifest.BundleID), log.F("mode", mode), log.F("mapping", cfg.Plan != nil))

	pre, err := mapRows(b, mapping.Context{Now: cfg.Now(), Actor: cfg.Actor, Rehearsal: cfg.Rehearsal, Plan: cfg.Plan})
	if err != nil {
		return nil, err
	}
	if len(pre.Rows["identity.user_totp"]) > 0 && cfg.TOTP == nil {
		return nil, codes.Wrap(codes.TargetKey, errors.New("the bundle has TOTP secrets but no target TOTP key was given (TARGET_TOTP_ENC_KEY)"))
	}

	dbs := map[schema.Service]*postgres.DB{}
	defer func() {
		for _, db := range dbs {
			db.Close()
		}
	}()
	versions := map[schema.Service]int64{}
	for _, s := range schema.Services {
		db, err := postgres.New(ctx, cfg.DSN[s])
		if err != nil {
			return nil, fmt.Errorf("connect to the target %s database: %w", s, err)
		}
		dbs[s] = db
		if versions[s], err = checkTargetVersion(ctx, db.Querier(), s); err != nil {
			return nil, err
		}
	}

	st, err := inspect(ctx, dbs, d.Kratos, b, pre.Expected())
	if err != nil {
		return nil, err
	}
	if cfg.Wipe {
		if !cfg.Rehearsal {
			imported, err := importedBefore(ctx, dbs[schema.Audit].Querier())
			if err != nil {
				return nil, err
			}
			if !imported && len(st.foreign) > 0 {
				return nil, codes.Wrap(codes.ModeRefused, fmt.Errorf("refusing to wipe: the target holds data that did not come from an import (%s); --wipe-target outside rehearsal mode only replaces an earlier import, so factory-reset the box instead", strings.Join(st.foreign, "; ")))
			}
			lg.Warn("re-import: wiping the earlier import", log.F("bundle_id", b.Manifest.BundleID))
		}
		if err := wipe(ctx, dbs, d.Kratos, lg); err != nil {
			return nil, err
		}
		rep.Wiped = true
		st = state{done: map[schema.Service]bool{}}
	} else if err := st.refuseForeign(); err != nil {
		return nil, err
	}

	ids, created, reused, err := importKratos(ctx, b, d.Kratos, lg)
	if err != nil {
		return nil, err
	}
	rep.KratosIdentities, rep.KratosCreated, rep.KratosReused = len(ids), created, reused

	m, err := mapRows(b, mapping.Context{Now: cfg.Now(), Actor: cfg.Actor, KratosIDs: ids, Rehearsal: cfg.Rehearsal, Plan: cfg.Plan})
	if err != nil {
		return nil, err
	}
	rep.Remap = m.Remap
	rep.Closed, rep.SSHTargetsToPin, rep.UsersWithoutSignIn = m.Closed, m.SSHTargets, m.Unlinked
	if rep.VersionSamples, err = matchVersionSamples(b, m); err != nil {
		return nil, err
	}
	lg.Info("older-version samples matched before sealing", log.F("values", rep.VersionSamples))
	rep.Security = settings.Review(m.Rows)
	for _, w := range rep.Security.Warnings {
		lg.Warn("security setting now restricts", log.F("warning", w))
	}

	for _, s := range writeOrder {
		if st.done[s] {
			rep.Services[string(s)] = "already imported (left as is)"
			lg.Info("service already imported", log.F("service", string(s)))
			continue
		}
		if err := prepare(ctx, s, m, cfg, d.Sealer, lg); err != nil {
			return nil, err
		}
		fillNewColumns(s, versions[s], m)
		if err := write(ctx, dbs[s], s, m); err != nil {
			return nil, fmt.Errorf("import %s: %w", s, err)
		}
		rep.Services[string(s)] = "imported"
		lg.Info("service imported", log.F("service", string(s)))
	}

	want := m.Expected()
	got := map[string]int{}
	for _, t := range schema.Tables {
		if !t.Carried() {
			continue
		}
		n, err := count(ctx, dbs[t.Service].Querier(), t.Name)
		if err != nil {
			return nil, err
		}
		got[t.Stream()] = n
		bt, _ := b.Manifest.Table(t.Stream())
		rep.Tables = append(rep.Tables, report.Count{Table: t.Stream(), Bundle: bt.Rows, Expected: want[t.Stream()], Target: n})
	}
	rep.Parity = CheckParity(b.Manifest, want, got, m.Remap)

	if rep.AuditEntries, err = appendAudit(ctx, dbs[schema.Audit].Querier(), d.Recorder, b, m, cfg, mode, rep.VersionSamples); err != nil {
		return nil, err
	}
	if err := ParityError(rep.Parity); err != nil {
		lg.Error(err, "import parity failed")
		rep.FinishedAt = cfg.Now().UTC().Format(time.RFC3339)
		return &Outcome{Report: rep}, err
	}

	out := &Outcome{Report: rep}
	if cfg.OwnerEmail != "" {
		pw, err := ownerPassword(ctx, d.Kratos, cfg.OwnerEmail)
		if err != nil {
			return nil, err
		}
		out.OwnerPassword, rep.OwnerPasswordSet = pw, true
		lg.Info("owner password replaced for the rehearsal", log.F("owner", cfg.OwnerEmail))
	}
	rep.Notes = append(rep.Notes, "restart the vault deployment so it loads the imported state")
	if len(rep.SSHTargetsToPin) > 0 {
		rep.Notes = append(rep.Notes, "brokered SSH to the listed targets is refused until an admin pins their host keys")
	}
	rep.FinishedAt = cfg.Now().UTC().Format(time.RFC3339)
	lg.Info("import finished", log.F("bundle_id", b.Manifest.BundleID), log.F("audit_entries", rep.AuditEntries))
	return out, nil
}

// writeOrder puts the audit chain first: the target vault audits every
// SealForImport call through the audit service, and those entries must append
// after the source chain, not take its first sequence numbers.
var writeOrder = []schema.Service{schema.Audit, schema.Identity, schema.Vault, schema.Workflow}

func checkTargetVersion(ctx context.Context, q postgres.Querier, s schema.Service) (int64, error) {
	var version int64
	var dirty bool
	query := "SELECT version, dirty FROM public." + schema.VersionTable(s) // #nosec G202 -- a fixed table name
	if err := q.QueryRow(ctx, query).Scan(&version, &dirty); err != nil {
		return 0, codes.Wrap(codes.TargetVersion, fmt.Errorf("the target %s database has no migration version (has the service started once?): %w", s, err))
	}
	if dirty || !schema.WritesTarget(s, version) {
		return 0, codes.Wrap(codes.TargetVersion, fmt.Errorf("the target %s database is at migration %d (dirty %t); this tool writes %v", s, version, dirty, schema.TargetVersions[s]))
	}
	return version, nil
}

// fillNewColumns gives rows that predate a target migration its new
// columns' values: jsonb_populate_recordset leaves a missing key NULL, not
// the column's default.
func fillNewColumns(s schema.Service, version int64, m *mapping.Result) {
	switch {
	case s == schema.Identity && version >= 2:
		for _, t := range m.Rows["identity.user_tokens"] {
			if _, ok := t["client_kind"]; ok {
				continue
			}
			// The earlier system kept no kind; its MCP tokens name the MCP
			// as their client, and everything else is a command-line token.
			t["client_kind"] = "cli"
			if strings.Contains(strings.ToLower(fmt.Sprint(t["client_name"])), "mcp") {
				t["client_kind"] = "mcp"
			}
		}
	case s == schema.Vault && version >= 2:
		for _, e := range m.Rows["vault.break_glass_events"] {
			if _, ok := e["session_id"]; !ok {
				e["session_id"] = ""
			}
		}
	}
}

func count(ctx context.Context, q postgres.Querier, table string) (int, error) {
	var n int
	if err := q.QueryRow(ctx, "SELECT count(*) FROM public."+table).Scan(&n); err != nil { // #nosec G202 -- names come from the fixed table list
		return 0, fmt.Errorf("count %s: %w", table, err)
	}
	return n, nil
}

// state is what the target already holds.
type state struct {
	done    map[schema.Service]bool
	foreign []string
}

func (s state) refuseForeign() error {
	if len(s.foreign) == 0 {
		return nil
	}
	return codes.Wrap(codes.TargetNotEmpty, fmt.Errorf("the target already holds data that is not this bundle's: %s (import needs a fresh install; --wipe-target is for rehearsals only)", strings.Join(s.foreign, "; ")))
}

// inspect classifies each service as empty, already imported (every table
// holds exactly the expected rows and the audit head matches), or foreign.
func inspect(ctx context.Context, dbs map[schema.Service]*postgres.DB, kr Kratos, b *bundle.Bundle, expected map[string]int) (state, error) {
	st := state{done: map[schema.Service]bool{}}
	for _, s := range schema.Services {
		q := dbs[s].Querier()
		empty, exact := true, true
		var held []string
		for _, t := range schema.Of(s) {
			if !t.Carried() {
				continue
			}
			n, err := count(ctx, q, t.Name)
			if err != nil {
				return st, err
			}
			if t.UserData && n > 0 {
				empty = false
				held = append(held, fmt.Sprintf("%s=%d", t.Name, n))
			}
			want := expected[t.Stream()]
			if s == schema.Audit {
				continue
			}
			if n != want {
				exact = false
			}
		}
		if s == schema.Audit {
			ok, err := auditHeadMatches(ctx, q, b.Manifest.AuditHead)
			if err != nil {
				return st, err
			}
			exact = ok && b.Manifest.AuditHead.Seq > 0
		}
		switch {
		case empty:
		case exact:
			st.done[s] = true
		default:
			st.foreign = append(st.foreign, string(s)+" ("+strings.Join(held, ", ")+")")
		}
	}
	ids, err := kr.List(ctx, false)
	if err != nil {
		return st, fmt.Errorf("target Kratos: %w", err)
	}
	if len(ids) > 0 {
		want := map[string]bool{}
		_ = b.Each(schema.KratosStream, func(raw []byte) error {
			var id kratos.Identity
			if json.Unmarshal(raw, &id) == nil {
				want[strings.ToLower(traitEmail(id))] = true
			}
			return nil
		})
		for _, id := range ids {
			if !want[strings.ToLower(traitEmail(id))] {
				st.foreign = append(st.foreign, fmt.Sprintf("kratos (%d identities, some not in the bundle)", len(ids)))
				break
			}
		}
	}
	return st, nil
}

func auditHeadMatches(ctx context.Context, q postgres.Querier, head bundle.Head) (bool, error) {
	var hash string
	err := q.QueryRow(ctx, "SELECT hash FROM public.audit_records WHERE seq = $1", int64(head.Seq)).Scan(&hash) // #nosec G115 -- audit seq fits in bigint
	if errors.Is(err, postgres.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return hash == head.Hash, nil
}

func traitEmail(id kratos.Identity) string {
	var t struct {
		Email string `json:"email"`
	}
	_ = json.Unmarshal(id.Traits, &t)
	return t.Email
}

// wipe empties every table this tool writes, and the target Kratos.
// Rehearsal only; the target's key ring is kept.
func wipe(ctx context.Context, dbs map[schema.Service]*postgres.DB, kr Kratos, lg log.Logger) error {
	for _, s := range schema.Services {
		var names []string
		for _, t := range schema.Of(s) {
			if t.Kind != schema.Replaced {
				names = append(names, "public."+t.Name)
			}
		}
		for _, t := range schema.TargetOnly {
			var exists bool
			if t.Service != s {
				continue
			}
			if err := dbs[s].Querier().QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", "public."+t.Name).Scan(&exists); err != nil {
				return fmt.Errorf("wipe %s: %w", s, err)
			}
			if exists {
				names = append(names, "public."+t.Name)
			}
		}
		err := dbs[s].RunInTx(ctx, func(tx postgres.Tx) error {
			if s == schema.Vault {
				if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", vaultWriteLock); err != nil {
					return err
				}
			}
			_, err := tx.Exec(ctx, "TRUNCATE "+strings.Join(names, ", ")) // #nosec G202 -- names come from the fixed table list
			return err
		})
		if err != nil {
			return fmt.Errorf("wipe %s: %w", s, err)
		}
	}
	ids, err := kr.List(ctx, false)
	if err != nil {
		return fmt.Errorf("wipe Kratos: %w", err)
	}
	for _, id := range ids {
		if err := kr.Delete(ctx, id.ID); err != nil {
			return fmt.Errorf("wipe Kratos: %w", err)
		}
	}
	lg.Warn("rehearsal target wiped", log.F("kratos_identities", len(ids)))
	return nil
}

// importKratos creates every bundle identity on the target, reusing one that
// already exists for the same address (a resumed import), and returns the
// old-to-new id map.
func importKratos(ctx context.Context, b *bundle.Bundle, kr Kratos, lg log.Logger) (map[string]string, int, int, error) {
	ids := map[string]string{}
	var created, reused int
	// An identity imported without credentials has no identifier Kratos can
	// search by, so a resumed import finds the earlier ones by address.
	have, err := byEmail(ctx, kr)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("target Kratos: %w", err)
	}
	err = b.Each(schema.KratosStream, func(raw []byte) error {
		var src kratos.Identity
		if err := json.Unmarshal(raw, &src); err != nil {
			return err
		}
		if nid, ok := have[strings.ToLower(traitEmail(src))]; ok && traitEmail(src) != "" {
			ids[src.ID] = nid
			reused++
			return nil
		}
		nid, err := kr.CreateFrom(ctx, src)
		if err != nil {
			return fmt.Errorf("identity %s: %w", src.ID, err)
		}
		ids[src.ID] = nid
		created++
		return nil
	})
	if err != nil {
		return nil, 0, 0, fmt.Errorf("target Kratos: %w", err)
	}
	lg.Info("kratos identities imported", log.F("created", created), log.F("reused", reused))
	return ids, created, reused, nil
}

// prepare turns opened values back into the target's stored form: TOTP
// secrets under the target key, vault fields re-sealed by the target vault.
func prepare(ctx context.Context, s schema.Service, m *mapping.Result, cfg Config, sealer Sealer, lg log.Logger) error {
	switch s {
	case schema.Identity:
		for _, r := range m.Rows["identity.user_totp"] {
			plain, _ := r["secret"].(string)
			sealed, err := cfg.TOTP.Seal(plain)
			if err != nil {
				return err
			}
			delete(r, "secret")
			r["encrypted_secret"] = sealed
		}
	case schema.Vault:
		for _, stream := range []string{"vault.secret_records", "vault.secret_versions"} {
			rows := m.Rows[stream]
			items := make([]map[string]string, len(rows))
			for i, r := range rows {
				f, err := fieldMap(r["fields"])
				if err != nil {
					return fmt.Errorf("%s: %w", stream, err)
				}
				items[i] = f
			}
			sealed, err := sealer.Seal(ctx, items)
			if err != nil {
				return err
			}
			for i, r := range rows {
				delete(r, "fields")
				r["record"] = json.RawMessage(sealed[i])
			}
			lg.Info("values re-sealed by the target vault", log.F("table", stream), log.F("rows", len(rows)))
		}
	}
	return nil
}

// matchVersionSamples checks each older-version sample against the opened
// value about to be sealed, so verify never has to reveal an older version.
// A mismatch means the bundle does not match its own manifest.
func matchVersionSamples(b *bundle.Bundle, m *mapping.Result) (int, error) {
	rows := map[string]mapping.Row{}
	for _, r := range m.Rows["vault.secret_versions"] {
		rows[fmt.Sprintf("%v@%v", r["secret_id"], r["version_no"])] = r
	}
	n := 0
	for _, s := range b.Manifest.Samples {
		if s.Version == 0 {
			continue
		}
		where := fmt.Sprintf("%s@%d", s.SecretID, s.Version)
		r, ok := rows[where]
		if !ok {
			return n, codes.Wrap(codes.BundleDamaged, fmt.Errorf("sample %s#%s: the bundle has no such version", where, s.Field))
		}
		f, err := fieldMap(r["fields"])
		if err != nil {
			return n, fmt.Errorf("vault.secret_versions %s: %w", where, err)
		}
		h := source.SampleHMAC(b.Manifest.SampleKey, s.SecretID, s.Version, s.Field, f[s.Field])
		if !hmac.Equal([]byte(h), []byte(s.HMAC)) {
			return n, codes.Wrap(codes.BundleDamaged, fmt.Errorf("sample %s#%s does not match the source", where, s.Field))
		}
		n++
	}
	return n, nil
}

func fieldMap(v any) (map[string]string, error) {
	m, ok := v.(map[string]any)
	if !ok {
		if v == nil {
			return map[string]string{}, nil
		}
		return nil, errors.New("fields is not an object")
	}
	out := make(map[string]string, len(m))
	for k, x := range m {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("field %q is not a string", k)
		}
		out[k] = s
	}
	return out, nil
}

// write inserts one service's rows in one transaction.
func write(ctx context.Context, db *postgres.DB, s schema.Service, m *mapping.Result) error {
	return db.RunInTx(ctx, func(tx postgres.Tx) error {
		if s == schema.Vault {
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", vaultWriteLock); err != nil {
				return fmt.Errorf("take the vault write lock: %w", err)
			}
		}
		for _, t := range schema.Of(s) {
			if !t.Carried() {
				continue
			}
			rows := m.Rows[t.Stream()]
			for start := 0; start < len(rows); start += insertChunk {
				end := min(start+insertChunk, len(rows))
				raw, err := json.Marshal(rows[start:end])
				if err != nil {
					return err
				}
				sql := fmt.Sprintf("INSERT INTO public.%[1]s SELECT * FROM jsonb_populate_recordset(NULL::public.%[1]s, $1::jsonb)", t.Name) // #nosec G201 -- names come from the fixed table list
				if t.Kind == schema.Seed {
					sql += fmt.Sprintf(" ON CONFLICT (%s) DO UPDATE SET data = EXCLUDED.data", strings.Join(t.Key, ", "))
				}
				if _, err := tx.Exec(ctx, sql, raw); err != nil {
					return fmt.Errorf("%s: %w", t.Stream(), err)
				}
			}
		}
		return nil
	})
}

// appendAudit appends the migration's own entries: one per item closed by
// migration, then the import summary. Entries already present for this
// bundle (a resumed import) are not appended twice.
func appendAudit(ctx context.Context, q postgres.Querier, rec Recorder, b *bundle.Bundle, m *mapping.Result, cfg Config, mode string, versionSamples int) (int, error) {
	have := map[string]bool{}
	rows, err := q.Query(ctx, "SELECT action, subject FROM public.audit_records WHERE attributes->>'bundle_id' = $1", b.Manifest.BundleID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var a, s string
		if err := rows.Scan(&a, &s); err != nil {
			rows.Close()
			return 0, err
		}
		have[a+"\x00"+s] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	emit := func(action, subject string, attrs map[string]string) error {
		if have[action+"\x00"+subject] {
			return nil
		}
		a := map[string]string{"bundle_id": b.Manifest.BundleID, "mode": mode}
		for k, v := range attrs {
			a[k] = v
		}
		if err := rec.Record(ctx, rpc.Event{Actor: cfg.Actor, Action: action, Subject: subject, Attributes: a}); err != nil {
			return fmt.Errorf("append audit entry %s: %w", action, err)
		}
		n++
		return nil
	}
	for _, e := range m.Events {
		if err := emit(e.Action, e.Subject, e.Attrs); err != nil {
			return n, err
		}
	}
	sum := map[string]string{
		"source_profile": b.Manifest.Profile, "source_head_seq": fmt.Sprint(b.Manifest.AuditHead.Seq),
		"source_head_hash": b.Manifest.AuditHead.Hash, "tables": fmt.Sprint(len(b.Manifest.Tables)),
		"version_samples_matched": fmt.Sprint(versionSamples),
	}
	for k, v := range m.Closed {
		sum["closed_"+strings.ReplaceAll(k, " ", "_")] = fmt.Sprint(v)
	}
	sum["current_only"], sum["sign_in_reset"] = fmt.Sprint(b.Manifest.CurrentOnly), fmt.Sprint(b.Manifest.SignInReset)
	if r := m.Remap; r != nil {
		sum["mapping_sha256"] = r.MappingSHA256
		sum["mapping_secrets_dropped"], sum["mapping_secrets_moved"] = fmt.Sprint(r.SecretsDropped), fmt.Sprint(r.SecretsMoved)
		sum["mapping_secrets_renamed"], sum["mapping_secrets_retyped"] = fmt.Sprint(r.SecretsRenamed), fmt.Sprint(r.SecretsRetyped)
		sum["mapping_folders_created"], sum["mapping_folders_moved"] = fmt.Sprint(r.FoldersCreated), fmt.Sprint(r.FoldersMoved)
		sum["mapping_folders_dropped"] = fmt.Sprint(r.FoldersDropped)
	}
	if err := emit("migration.import", "bundle:"+b.Manifest.BundleID, sum); err != nil {
		return n, err
	}
	return n, nil
}

func ownerPassword(ctx context.Context, kr Kratos, email string) (string, error) {
	have, err := byEmail(ctx, kr)
	if err != nil {
		return "", fmt.Errorf("owner account %s: %w", email, err)
	}
	id, ok := have[strings.ToLower(email)]
	if !ok {
		return "", fmt.Errorf("owner account %s: %w", email, kratos.ErrNotFound)
	}
	pw, err := kratos.RandomPassword(24)
	if err != nil {
		return "", err
	}
	if err := kr.SetPassword(ctx, id, pw); err != nil {
		return "", fmt.Errorf("owner account %s: %w", email, err)
	}
	return pw, nil
}

// checkMode refuses the flag combinations a mode doesn't allow.
func checkMode(cfg Config, b *bundle.Bundle) error {
	if b.Manifest.Sanitised && !cfg.Rehearsal {
		return codes.Wrap(codes.ModeRefused, errors.New("the bundle is sanitised (fake values for a lab dry run); import it with --rehearsal only"))
	}
	if cfg.Plan != nil && cfg.Plan.BundleID != "" && cfg.Plan.BundleID != b.Manifest.BundleID {
		return codes.Wrap(codes.MappingInvalid, fmt.Errorf("the mapping file is for bundle %s, not %s; convert or check it against this bundle", cfg.Plan.BundleID, b.Manifest.BundleID))
	}
	if cfg.Rehearsal {
		return nil
	}
	if cfg.Plan == nil {
		return codes.Wrap(codes.ModeRefused, errors.New("an import outside rehearsal mode needs the owner's approved mapping file (--mapping)"))
	}
	if !b.Manifest.CurrentOnly || !b.Manifest.SignInReset {
		return codes.Wrap(codes.ModeRefused, errors.New("an import outside rehearsal mode takes a bundle exported with --current-only and --reset-sign-in: every sign-in is reset and each secret carries its current value only"))
	}
	if cfg.Plan.BundleID == "" {
		return codes.Wrap(codes.MappingInvalid, errors.New("the mapping file names no bundle_id; outside rehearsal mode it must be keyed to this bundle (review --template and mapping --tsv write it)"))
	}
	return nil
}

// mapRows maps the bundle, marking a mapping file that doesn't fit it.
func mapRows(b *bundle.Bundle, c mapping.Context) (*mapping.Result, error) {
	m, err := mapping.Map(b, c)
	if errors.Is(err, mapping.ErrMapping) {
		return nil, codes.Wrap(codes.MappingInvalid, err)
	}
	return m, err
}

// importedBefore reports whether the target's audit chain records an import.
func importedBefore(ctx context.Context, q postgres.Querier) (bool, error) {
	var n int
	if err := q.QueryRow(ctx, "SELECT count(*) FROM public.audit_records WHERE action = 'migration.import'").Scan(&n); err != nil {
		return false, fmt.Errorf("read the target audit chain: %w", err)
	}
	return n > 0, nil
}

func byEmail(ctx context.Context, kr Kratos) (map[string]string, error) {
	list, err := kr.List(ctx, false)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, id := range list {
		if e := strings.ToLower(traitEmail(id)); e != "" {
			out[e] = id.ID
		}
	}
	return out, nil
}

// CheckParity compares each category's source, bundle, mapped and target
// counts: what the source held, less what the mapping dropped, plus the
// folders it made, must be what the target holds.
func CheckParity(m bundle.Manifest, expected, target map[string]int, remap *mapping.RemapStats) []report.Parity {
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

// ParityError is the loud failure for a parity table with a mismatch.
func ParityError(ps []report.Parity) error {
	var bad []string
	for _, p := range ps {
		if !p.OK {
			bad = append(bad, fmt.Sprintf("%s: source %d, dropped %d, created %d, expected %d, target %d", p.Name, p.Source, p.Dropped, p.Created, p.Expected, p.Target))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return codes.Wrap(codes.ParityMismatch, fmt.Errorf("import parity failed (%s); fix the cause and re-import with --wipe-target", strings.Join(bad, "; ")))
}
