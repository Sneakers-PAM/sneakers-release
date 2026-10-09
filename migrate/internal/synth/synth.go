// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package synth lays down an invented dataset in the original system's schema:
// users with passwords and TOTP, groups, folders and rules, secrets with
// several versions sealed under an invented key ring, targets, schedules, open
// approvals and check-outs, and a valid audit chain. It feeds the synthetic
// rehearsal and the integration tests. Every name is invented (example.org),
// and every key is generated for the run.
package synth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"sort"
	"strings"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-release/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/chain"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/envelope"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/totpcipher"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Options sizes the dataset. Zero values take the rehearsal defaults.
type Options struct {
	Users        int
	Secrets      int
	AuditRecords int
	Seed         uint64
	// OwnerEmail is the root user's address.
	OwnerEmail string
	// Shape lays the vault out to a plan (Shape); nil is the default tree.
	Shape *Shape
}

func (o *Options) defaults() {
	if o.Users == 0 {
		o.Users = 30
	}
	if o.Secrets == 0 {
		o.Secrets = 200
	}
	if o.AuditRecords == 0 {
		o.AuditRecords = 1000
	}
	if o.Seed == 0 {
		o.Seed = 20261002
	}
	if o.OwnerEmail == "" {
		o.OwnerEmail = "owner@example.org"
	}
}

// Keys are the invented source keys the dataset is sealed under.
type Keys struct {
	RootKey []byte
	DevSeed string
	TOTPKey []byte
}

// NewKeys generates fresh source keys.
func NewKeys() (Keys, error) {
	k := Keys{RootKey: make([]byte, 32), TOTPKey: make([]byte, 32)}
	if _, err := rand.Read(k.RootKey); err != nil {
		return Keys{}, err
	}
	if _, err := rand.Read(k.TOTPKey); err != nil {
		return Keys{}, err
	}
	seed := make([]byte, 12)
	if _, err := rand.Read(seed); err != nil {
		return Keys{}, err
	}
	k.DevSeed = "synthetic-dev-seed-" + hex.EncodeToString(seed)
	return k, nil
}

// RootKeyB64 is the root key as VAULT_ROOT_KEK carries it.
func (k Keys) RootKeyB64() string { return base64.StdEncoding.EncodeToString(k.RootKey) }

// TOTPKeyB64 is the TOTP key as TOTP_ENC_KEY carries it.
func (k Keys) TOTPKeyB64() string { return base64.StdEncoding.EncodeToString(k.TOTPKey) }

// KratosSeeder creates the source Kratos identities.
type KratosSeeder interface {
	CreateWithPassword(ctx context.Context, email, first, last, password string) (string, error)
}

// Summary is what Seed laid down: row counts per stream and the Kratos users.
type Summary struct {
	Rows   map[string]int
	Kratos int
	// Retired lists retired secret ids (reveals are refused for these).
	Retired []string
}

// Migrate applies a migration directory to each database with golang-migrate,
// as the original services did on boot.
func Migrate(dsn map[schema.Service]string, dirs map[schema.Service]string) error {
	for _, s := range schema.Services {
		if err := postgres.MigrateWithTable(dsn[s], dirs[s], schema.VersionTable(s)); err != nil {
			return fmt.Errorf("migrate %s: %w", s, err)
		}
	}
	return sagaStandIn(dsn[schema.Workflow])
}

// sagaStandIn gives the workflow database the go-saga engine's version table
// at a version other than the service's, as a real workflow database has it.
func sagaStandIn(dsn string) error {
	ctx := context.Background()
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("saga stand-in: %w", err)
	}
	defer db.Close()
	for _, sql := range []string{
		"CREATE TABLE IF NOT EXISTS public.schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)",
		"DELETE FROM public.schema_migrations",
		"INSERT INTO public.schema_migrations (version, dirty) VALUES (10, false)",
	} {
		if _, err := db.Querier().Exec(ctx, sql); err != nil {
			return fmt.Errorf("saga stand-in: %w", err)
		}
	}
	return nil
}

var (
	firstNames = []string{"Avery", "Blake", "Casey", "Devon", "Emery", "Finley", "Gray", "Harper", "Indy", "Jules", "Kai", "Lane", "Morgan", "Noel", "Oakley", "Parker", "Quinn", "Reese", "Sage", "Tatum", "Umber", "Vale", "Wren", "Xen", "Yael", "Zion", "Arden", "Brook", "Cove", "Dale", "Ellis", "Fern"}
	lastNames  = []string{"Ashdown", "Birchfield", "Copperly", "Dunmore", "Elmstead", "Foxglove", "Greystone", "Hollins", "Ironwood", "Juniper", "Kestrel", "Larkspur", "Millbrook", "Northcott", "Oakhurst", "Pennywhistle"}
	groupNames = []string{"Server Admins", "Network Team", "Database Admins", "Help Desk", "Security", "Auditors"}
	actions    = []string{"secret.reveal", "secret.copy", "secret.create", "secret.update", "folder.create", "auth.login", "auth.mfa", "secret.rotate", "secret.heartbeat", "workflow.request", "workflow.approve", "group.member.add"}
)

type gen struct {
	r     *mrand.Rand
	now   time.Time
	ring  *envelope.Keyring
	totp  *totpcipher.Cipher
	opts  Options
	sum   *Summary
	users []user
}

type user struct {
	id, email, first, last, kratosID string
	root, admin, disabled            bool
}

// Seed fills the source databases and Kratos. The databases must hold the
// source schema and no rows.
func Seed(ctx context.Context, dbs map[schema.Service]*postgres.DB, kr KratosSeeder, keys Keys, opts Options) (*Summary, error) {
	opts.defaults()
	g := &gen{
		// The seeded generator only shapes the dataset (which folder, how many
		// versions, when); every key, token and password comes from crypto/rand.
		r:    mrand.New(mrand.NewPCG(opts.Seed, opts.Seed^0x5eed)), // #nosec G404 -- shape only, see above
		now:  time.Now().UTC().Truncate(time.Second),
		opts: opts, sum: &Summary{Rows: map[string]int{}},
	}
	k1, k2 := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(k1); err != nil {
		return nil, err
	}
	if _, err := rand.Read(k2); err != nil {
		return nil, err
	}
	w1, err := envelope.WrapKey(keys.RootKey, k1)
	if err != nil {
		return nil, err
	}
	w2, err := envelope.WrapKey(keys.RootKey, k2)
	if err != nil {
		return nil, err
	}
	ringRows := []envelope.KeyringRow{
		{Ref: "kek-v1", WrappedKey: w1, RootRef: "root-v1"},
		{Ref: "kek-v2", WrappedKey: w2, RootRef: "root-v1", Active: true},
	}
	if g.ring, err = envelope.LoadKeyring(ringRows, keys.RootKey, keys.DevSeed); err != nil {
		return nil, err
	}
	if g.totp, err = totpcipher.New(keys.TOTPKey); err != nil {
		return nil, err
	}
	if err := g.identity(ctx, dbs[schema.Identity], kr); err != nil {
		return nil, fmt.Errorf("seed identity: %w", err)
	}
	seedVault := g.vault
	if opts.Shape != nil {
		seedVault = g.vaultShaped
	}
	if err := seedVault(ctx, dbs[schema.Vault], ringRows); err != nil {
		return nil, fmt.Errorf("seed vault: %w", err)
	}
	if err := g.workflow(ctx, dbs[schema.Workflow]); err != nil {
		return nil, fmt.Errorf("seed workflow: %w", err)
	}
	if err := g.audit(ctx, dbs[schema.Audit]); err != nil {
		return nil, fmt.Errorf("seed audit: %w", err)
	}
	return g.sum, nil
}

// insert writes one row given as column/value pairs.
func (g *gen) insert(ctx context.Context, q postgres.Querier, svc schema.Service, table string, row map[string]any) error {
	cols := make([]string, 0, len(row))
	for c := range row {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	args := make([]any, len(cols))
	ph := make([]string, len(cols))
	for i, c := range cols {
		args[i] = row[c]
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	sql := fmt.Sprintf("INSERT INTO public.%s (%s) VALUES (%s)", table, strings.Join(cols, ", "), strings.Join(ph, ", ")) // #nosec G201 -- table and column names are fixed in this file
	if _, err := q.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("%s: %w", table, err)
	}
	g.sum.Rows[string(svc)+"."+table]++
	return nil
}

func (g *gen) user(i int) user { return g.users[i%len(g.users)] }

func (g *gen) pick(n int) int { return g.r.IntN(n) }

// randBytes returns n random bytes for invented key material and tokens.
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func (g *gen) token(n int) string { return hex.EncodeToString(randBytes(n)) }

func (g *gen) password() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*-_=+"
	raw := randBytes(16 + g.pick(12))
	for i := range raw {
		raw[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(raw)
}

func (g *gen) ago(maxDays int) time.Time {
	return g.now.Add(-time.Duration(g.r.Int64N(int64(maxDays)*24*int64(time.Hour))) - time.Hour)
}

func (g *gen) identity(ctx context.Context, db *postgres.DB, kr KratosSeeder) error {
	q := db.Querier()
	for i := 0; i < g.opts.Users; i++ {
		u := user{
			id:    fmt.Sprintf("usr-%04d", i+1),
			first: firstNames[i%len(firstNames)], last: lastNames[(i*7)%len(lastNames)],
		}
		u.email = strings.ToLower(fmt.Sprintf("%s.%s@example.org", u.first, u.last))
		if i == 0 {
			u.email, u.root, u.admin = g.opts.OwnerEmail, true, true
		}
		u.admin = u.admin || i%9 == 3
		u.disabled = i == g.opts.Users-2
		// The last user predates the sign-in move: no Kratos identity.
		if i < g.opts.Users-1 {
			id, err := kr.CreateWithPassword(ctx, u.email, u.first, u.last, g.password())
			if err != nil {
				return fmt.Errorf("kratos identity %d: %w", i+1, err)
			}
			u.kratosID = id
			g.sum.Kratos++
		}
		roles := []string{}
		if u.admin {
			roles = []string{"site-admin"}
		}
		row := map[string]any{
			"id": u.id, "name": u.first + " " + u.last, "email": u.email, "roles": roles,
			"is_root": u.root, "keycloak_subject": u.kratosID, "username": strings.Split(u.email, "@")[0],
			"email_verified": i%5 != 4,
		}
		if u.disabled {
			row["disabled_at"] = g.ago(30)
		}
		if err := g.insert(ctx, q, schema.Identity, "users", row); err != nil {
			return err
		}
		g.users = append(g.users, u)
	}
	for i, name := range groupNames {
		if err := g.insert(ctx, q, schema.Identity, "groups", map[string]any{"id": fmt.Sprintf("grp-%02d", i+1), "name": name}); err != nil {
			return err
		}
	}
	for i, u := range g.users {
		for gi := range groupNames {
			if (i+gi)%3 != 0 {
				continue
			}
			row := map[string]any{"user_id": u.id, "group_id": fmt.Sprintf("grp-%02d", gi+1), "added_at": g.ago(300), "added_by_user_id": g.user(0).id}
			if err := g.insert(ctx, q, schema.Identity, "group_membership", row); err != nil {
				return err
			}
		}
	}
	for i := 0; i < 3; i++ {
		said := fmt.Sprintf("sa-%02d", i+1)
		row := map[string]any{"id": said, "name": fmt.Sprintf("automation-%d", i+1), "description": "Synthetic service account", "created_by": g.user(0).id, "created_at": g.ago(200), "oidc_allowed_groups": []string{}}
		if i == 2 {
			row["oidc_issuer"], row["oidc_subject"] = "https://ci.example.org", "repo:example/deploy"
			row["oidc_allowed_groups"] = []string{"grp-01"}
		}
		if err := g.insert(ctx, q, schema.Identity, "service_accounts", row); err != nil {
			return err
		}
		for j := 0; j < 1+i%2; j++ {
			tok := map[string]any{"id": fmt.Sprintf("tok-%s-%d", said, j), "service_account_id": said, "token_hash": g.token(32), "scope": "read", "created_by": g.user(0).id, "created_at": g.ago(100)}
			if err := g.insert(ctx, q, schema.Identity, "api_tokens", tok); err != nil {
				return err
			}
		}
	}
	for i := 0; i < 5; i++ {
		u := g.user(i + 1)
		row := map[string]any{"id": fmt.Sprintf("utk-%02d", i+1), "user_id": u.id, "token_hash": g.token(32), "label": "laptop", "client_name": "mcp", "created_at": g.ago(40)}
		if i == 4 {
			row["revoked_at"] = g.ago(5)
		}
		if err := g.insert(ctx, q, schema.Identity, "user_tokens", row); err != nil {
			return err
		}
	}
	for i, u := range g.users {
		if i%3 == 2 {
			continue
		}
		raw := randBytes(20)
		sealed, err := g.totp.Seal(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
		if err != nil {
			return err
		}
		row := map[string]any{"user_id": u.id, "encrypted_secret": sealed, "confirmed_at": g.ago(90), "created_at": g.ago(120), "updated_at": g.ago(10)}
		if err := g.insert(ctx, q, schema.Identity, "user_totp", row); err != nil {
			return err
		}
	}
	for i := 0; i < 6; i++ {
		u := g.user(i * 4)
		pk := randBytes(77)
		row := map[string]any{
			"credential_id": base64.RawURLEncoding.EncodeToString([]byte(g.token(16))), "user_id": u.id, "public_key": pk,
			"sign_count": int64(g.pick(400)), "aaguid": pk[:16], "transports": []string{"usb", "nfc"}, "backup_eligible": i%2 == 0,
			"label": fmt.Sprintf("security key %d", i+1), "created_at": g.ago(150),
		}
		if err := g.insert(ctx, q, schema.Identity, "user_webauthn_credentials", row); err != nil {
			return err
		}
	}
	for i := 0; i < 3; i++ {
		row := map[string]any{"user_id": g.user(i + 2).id, "purpose": "login", "code_hash": g.token(32), "expires_at": g.now.Add(10 * time.Minute)}
		if err := g.insert(ctx, q, schema.Identity, "user_email_otp", row); err != nil {
			return err
		}
	}
	for i := 0; i < 2; i++ {
		row := map[string]any{"session_id": g.token(16), "user_id": g.user(i + 3).id, "purpose": "register", "data_json": "{}", "expires_at": g.now.Add(5 * time.Minute)}
		if err := g.insert(ctx, q, schema.Identity, "webauthn_sessions", row); err != nil {
			return err
		}
	}
	return nil
}

func pj(m proto.Message) ([]byte, error) { return protojson.Marshal(m) }

type stype struct {
	t         *vaultv1.SecretType
	sensitive []string
}

func sensitiveOf(t *vaultv1.SecretType) []string {
	var out []string
	for _, f := range t.GetFields() {
		if f.GetKind() == vaultv1.FieldKind_FIELD_KIND_PASSWORD || f.GetSensitive() {
			out = append(out, f.GetKey())
		}
	}
	return out
}

func secretTypes() []*vaultv1.SecretType {
	sys := vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM
	text, pw, sens := vaultv1.FieldKind_FIELD_KIND_TEXT, vaultv1.FieldKind_FIELD_KIND_PASSWORD, vaultv1.FieldKind_FIELD_KIND_SENSITIVE
	return []*vaultv1.SecretType{
		{Id: "type-password", Name: "Password", Origin: sys, Rotation: true, Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Label: "Username", Kind: text}, {Key: "password", Label: "Password", Kind: pw, Rotates: true, Required: true}, {Key: "notes", Label: "Notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE}}},
		{Id: "type-ssh-key", Name: "SSH Key", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Label: "Username", Kind: text}, {Key: "private_key", Label: "Private key", Kind: sens, Sensitive: true, SuperSensitive: true}, {Key: "passphrase", Label: "Passphrase", Kind: pw}}},
		{Id: "type-active-directory", Name: "Active Directory Account", Origin: sys, Heartbeat: true, Checkout: true, Rotation: true, Fields: []*vaultv1.SecretFieldDef{
			{Key: "domain", Label: "Domain", Kind: text}, {Key: "username", Label: "Username", Kind: text}, {Key: "password", Label: "Password", Kind: pw, Rotates: true}}},
		{Id: "type-unix-ssh", Name: "Password Account (SSH)", Origin: sys, Heartbeat: true, Rotation: true, Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Label: "Username", Kind: text}, {Key: "password", Label: "Password", Kind: pw, Rotates: true}}},
		{Id: "type-api-token", Name: "API Token", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			{Key: "token", Label: "Token", Kind: sens, Sensitive: true}, {Key: "url", Label: "URL", Kind: text}}},
		{Id: "custom-lab-badge", Name: "Lab Door Code", Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_CUSTOM, Fields: []*vaultv1.SecretFieldDef{
			{Key: "code", Label: "Code", Kind: pw}}},
	}
}

func (g *gen) fieldsFor(t *vaultv1.SecretType, n int) map[string]string {
	f := map[string]string{}
	for _, d := range t.GetFields() {
		switch d.GetKey() {
		case "username":
			f["username"] = fmt.Sprintf("svc-%03d", n)
		case "domain":
			f["domain"] = "CORP"
		case "url":
			f["url"] = fmt.Sprintf("https://app%02d.example.org", n%20)
		case "notes":
			if n%4 == 0 {
				f["notes"] = "line one\nline two"
			}
		case "private_key":
			f["private_key"] = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + g.token(48) + "\n-----END OPENSSH PRIVATE KEY-----\n"
		case "code":
			f["code"] = fmt.Sprintf("%06d", g.pick(1000000))
		default:
			f[d.GetKey()] = g.password()
		}
	}
	return f
}

func (g *gen) seal(ref string, fields map[string]string) ([]byte, error) {
	rec, err := g.ring.SealWith(ref, fields)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rec)
}

func (g *gen) vault(ctx context.Context, db *postgres.DB, ring []envelope.KeyringRow) error {
	q := db.Querier()
	for i, r := range ring {
		row := map[string]any{"ref": r.Ref, "wrapped_key": r.WrappedKey, "root_ref": r.RootRef, "active": r.Active, "created_at": g.ago(400 - i*300)}
		if !r.Active {
			row["retired_at"] = g.ago(60)
		}
		if err := g.insert(ctx, q, schema.Vault, "kek_keyring", row); err != nil {
			return err
		}
	}
	types := secretTypes()
	var st []stype
	for _, t := range types {
		raw, err := pj(t)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "secret_types", map[string]any{"id": t.GetId(), "data": raw}); err != nil {
			return err
		}
		st = append(st, stype{t: t, sensitive: sensitiveOf(t)})
	}
	for _, ext := range []*vaultv1.SecretType{
		{Id: "ext-aws-iam-key", Name: "Amazon IAM Access Key", Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION, Vendor: "Amazon Web Services"},
		{Id: "ext-gcp-sa-key", Name: "Google Cloud Service Account Key", Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION, Vendor: "Google Cloud"},
	} {
		raw, err := pj(ext)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "extension_catalog", map[string]any{"id": ext.GetId(), "data": raw}); err != nil {
			return err
		}
	}
	maxLen := int32(64)
	pol, err := pj(&vaultv1.PasswordPolicy{Id: "pwpolicy-default", Name: "Default", MinLength: 16, MaxLength: &maxLen, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true})
	if err != nil {
		return err
	}
	if err := g.insert(ctx, q, schema.Vault, "password_policies", map[string]any{"id": "pwpolicy-default", "data": pol}); err != nil {
		return err
	}
	set, err := pj(&vaultv1.SecuritySettings{DefaultPasswordPolicyId: "pwpolicy-default", RequireMfaForSensitiveCheckout: true, SessionTtlSeconds: 1800, KekRotationDays: 90})
	if err != nil {
		return err
	}
	if err := g.insert(ctx, q, schema.Vault, "security_settings", map[string]any{"id": 1, "data": set}); err != nil {
		return err
	}

	// Folders: the personal root, a personal folder for some users, and a shared tree.
	type folder struct{ id, name, parent string }
	folders := []*vaultv1.Folder{{Id: "folder-personal-root", Name: "Personal", IsMasterPersonal: true, Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL}}
	for i := 0; i < 10; i++ {
		folders = append(folders, &vaultv1.Folder{Id: fmt.Sprintf("folder-personal-%02d", i+1), Name: "Personal", ParentId: "folder-personal-root", Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: g.user(i).id})
	}
	shared := []folder{
		{"folder-infra", "Infrastructure", ""}, {"folder-linux", "Linux", "folder-infra"}, {"folder-windows", "Windows", "folder-infra"},
		{"folder-network", "Network", "folder-infra"}, {"folder-db", "Databases", ""}, {"folder-db-prod", "Production", "folder-db"},
		{"folder-db-test", "Test", "folder-db"}, {"folder-apps", "Applications", ""}, {"folder-apps-web", "Web", "folder-apps"},
		{"folder-apps-api", "API keys", "folder-apps"}, {"folder-sec", "Security", ""}, {"folder-sec-break", "Break glass", "folder-sec"},
		{"folder-helpdesk", "Help Desk", ""}, {"folder-lab", "Lab", ""}, {"folder-lab-doors", "Doors", "folder-lab"},
	}
	var sharedIDs []string
	for i, f := range shared {
		folders = append(folders, &vaultv1.Folder{Id: f.id, Name: f.name, ParentId: f.parent, Order: int32(i), Owners: []string{g.user(i % 4).id}})
		sharedIDs = append(sharedIDs, f.id)
	}
	for _, f := range folders {
		raw, err := pj(f)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "folders", map[string]any{"id": f.GetId(), "data": raw}); err != nil {
			return err
		}
	}
	for i := 0; i < 10; i++ {
		r := &vaultv1.FolderAccessRule{Id: fmt.Sprintf("frule-%02d", i+1), FolderId: sharedIDs[i], SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectId: fmt.Sprintf("grp-%02d", i%len(groupNames)+1), Role: vaultv1.FolderRole(1 + i%5)}
		raw, err := pj(r)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "folder_rules", map[string]any{"id": r.GetId(), "data": raw}); err != nil {
			return err
		}
	}
	for i := 0; i < 15; i++ {
		order := int32(i / len(sharedIDs)) // #nosec G115 -- a loop index below 15
		r := &vaultv1.RaciRule{Id: fmt.Sprintf("raci-%02d", i+1), FolderId: sharedIDs[i%len(sharedIDs)], Order: order, SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: groupNames[i%len(groupNames)], Grants: map[string]string{"C": "allow", "R": "allow"}}
		if i%5 == 4 {
			r.SubjectKind, r.SubjectName, r.Grants = vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE, "", map[string]string{"C": "deny"}
		}
		raw, err := pj(r)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "raci_rules", map[string]any{"id": r.GetId(), "data": raw}); err != nil {
			return err
		}
	}

	// Connections and targets: SSH hosts and AD domains.
	conns := []*vaultv1.Connection{
		{Id: "conn-ssh-default", Name: "Default SSH", Protocol: "ssh", Port: 22, Description: "Standard SSH to Unix/Linux hosts."},
		{Id: "conn-winrm-default", Name: "Default WinRM", Protocol: "winrm", Port: 5986, UseTls: true, Description: "WinRM over HTTPS to Windows hosts."},
		{Id: "conn-ldaps", Name: "Directory (LDAPS)", Protocol: "ldap", Port: 636, UseTls: true, Description: "Active Directory / LDAP over TLS."},
		{Id: "conn-ldaps-corp", Name: "Corp directory", Protocol: "ldap", Port: 636, UseTls: true, PrivilegedSecretId: "sec-0003"},
	}
	for _, c := range conns {
		raw, err := pj(c)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "connections", map[string]any{"id": c.GetId(), "data": raw}); err != nil {
			return err
		}
	}
	var sshTargets, adTargets []string
	for i := 0; i < 15; i++ {
		t := &vaultv1.Target{Id: fmt.Sprintf("tgt-%02d", i+1)}
		if i < 10 {
			t.Name, t.Hostname, t.ConnectionId, t.Kind = fmt.Sprintf("linux-%02d", i+1), fmt.Sprintf("host%02d.example.org", i+1), "conn-ssh-default", "ssh"
			sshTargets = append(sshTargets, t.Id)
		} else {
			t.Name, t.Hostname, t.ConnectionId, t.Kind = fmt.Sprintf("dc%02d", i-9), fmt.Sprintf("dc%02d.corp.example.org", i-9), "conn-ldaps-corp", "ad"
			t.Domain, t.Realm = "CORP", "CORP.EXAMPLE.ORG"
			adTargets = append(adTargets, t.Id)
		}
		if i == 7 {
			t.OwnerUserId = g.user(2).id
		}
		raw, err := pj(t)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "targets", map[string]any{"id": t.GetId(), "data": raw}); err != nil {
			return err
		}
	}
	for i := 0; i < 3; i++ {
		r := &vaultv1.RaciRule{Id: fmt.Sprintf("traci-%02d", i+1), Order: int32(i), SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: groupNames[i], Grants: map[string]string{"R": "allow"}}
		raw, err := pj(r)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "target_raci_rules", map[string]any{"id": r.GetId(), "target_id": sshTargets[i], "data": raw}); err != nil {
			return err
		}
	}

	// Secrets with their versions.
	for i := 0; i < g.opts.Secrets; i++ {
		id := fmt.Sprintf("sec-%04d", i+1)
		t := st[i%len(st)]
		sec := &vaultv1.Secret{Id: id, Name: fmt.Sprintf("%s %03d", t.t.GetName(), i+1), TypeId: t.t.GetId()}
		switch {
		case i < 20:
			sec.FolderId = fmt.Sprintf("folder-personal-%02d", i%10+1)
		default:
			sec.FolderId = sharedIDs[i%len(sharedIDs)]
		}
		switch t.t.GetId() {
		case "type-unix-ssh", "type-ssh-key":
			sec.TargetId = sshTargets[i%len(sshTargets)]
		case "type-active-directory":
			sec.TargetId = adTargets[i%len(adTargets)]
		}
		if i%40 == 39 {
			sec.Retired, sec.RetiredAt = true, g.ago(20).Format(time.RFC3339)
			g.sum.Retired = append(g.sum.Retired, id)
		}
		if t.t.GetRotation() {
			sec.RotationIntervalDays = 30
		}
		if t.t.GetHeartbeat() {
			sec.HeartbeatIntervalSeconds = 3600
		}
		versions := 2 + i%4
		var cur map[string]string
		for v := 1; v <= versions; v++ {
			fields := g.fieldsFor(t.t, i)
			ref := "kek-v2"
			switch {
			case v == 1 && i%3 == 0:
				ref = envelope.DevStaticRef
			case v < versions:
				ref = "kek-v1"
			}
			raw, err := g.seal(ref, fields)
			if err != nil {
				return err
			}
			row := map[string]any{"secret_id": id, "version_no": v, "record": raw, "active": v == versions, "created_at": g.ago(400 - v*50), "created_by": g.user((i + v)).id}
			if err := g.insert(ctx, q, schema.Vault, "secret_versions", row); err != nil {
				return err
			}
			if v == versions {
				cur = fields
			}
		}
		if i%50 == 7 {
			staged, err := g.seal("kek-v2", g.fieldsFor(t.t, i+1000))
			if err != nil {
				return err
			}
			row := map[string]any{"secret_id": id, "version_no": versions + 1, "record": staged, "staged": true, "created_by": "system:rotation"}
			if err := g.insert(ctx, q, schema.Vault, "secret_versions", row); err != nil {
				return err
			}
		}
		rec, err := g.seal("kek-v2", cur)
		if err != nil {
			return err
		}
		if i%10 == 5 {
			if rec, err = g.seal("kek-v1", cur); err != nil {
				return err
			}
		}
		if err := g.insert(ctx, q, schema.Vault, "secret_records", map[string]any{"secret_id": id, "record": rec}); err != nil {
			return err
		}
		raw, err := pj(sec)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "secrets", map[string]any{"id": id, "data": raw}); err != nil {
			return err
		}
		if t.t.GetRotation() && !sec.Retired {
			row := map[string]any{"secret_id": id, "next_rotation_at": g.now.Add(time.Duration(1+i%30) * 24 * time.Hour), "interval_days": 30, "state": 1}
			if i%33 == 0 {
				row["claimed_until"] = g.now.Add(5 * time.Minute)
				row["state"] = 4
			}
			if err := g.insert(ctx, q, schema.Vault, "rotation_schedule", row); err != nil {
				return err
			}
		}
		if t.t.GetHeartbeat() && !sec.Retired {
			row := map[string]any{"secret_id": id, "next_heartbeat_at": g.now.Add(time.Duration(i%60) * time.Minute), "interval_seconds": 3600}
			if err := g.insert(ctx, q, schema.Vault, "heartbeat_schedule", row); err != nil {
				return err
			}
		}
	}

	// Uses without reveal, grants, break-glass.
	for i := 0; i < 6; i++ {
		state := []vaultv1.SecretUseState{1, 1, 1, 2, 4, 4}[i]
		u := &vaultv1.SecretUse{Id: fmt.Sprintf("use-%02d", i+1), SecretId: fmt.Sprintf("sec-%04d", 21+i), FieldKey: "password", Argv: []string{"psql", "-h", "db01.example.org"}, UserId: g.user(1).id, TokenId: "utk-01", State: state, CreatedAtUnix: g.ago(2).Unix(), ExpiresAtUnix: g.now.Add(time.Hour).Unix()}
		raw, err := pj(u)
		if err != nil {
			return err
		}
		row := map[string]any{"id": u.GetId(), "user_id": u.GetUserId(), "state": int(state), "expires_at": g.now.Add(time.Hour), "data": raw}
		if err := g.insert(ctx, q, schema.Vault, "secret_uses", row); err != nil {
			return err
		}
	}
	for i := 0; i < 3; i++ {
		gr := &vaultv1.UseGrant{Id: fmt.Sprintf("grant-%02d", i+1), UserId: g.user(1).id, TokenId: "utk-01", SecretIds: []string{fmt.Sprintf("sec-%04d", 21+i)}, ExpiresAtUnix: g.now.Add(72 * time.Hour).Unix(), CreatedAtUnix: g.ago(3).Unix()}
		raw, err := pj(gr)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "secret_use_grants", map[string]any{"id": gr.GetId(), "user_id": gr.GetUserId(), "data": raw}); err != nil {
			return err
		}
	}
	for i := 0; i < 2; i++ {
		row := map[string]any{"id": fmt.Sprintf("bg-%02d", i+1), "secret_id": fmt.Sprintf("sec-%04d", 100+i), "actor_user_id": g.user(0).id, "reason": "outage drill", "occurred_at": g.ago(50), "post_rotation_scheduled": true, "notified": true}
		if err := g.insert(ctx, q, schema.Vault, "break_glass_events", row); err != nil {
			return err
		}
	}
	return nil
}

func (g *gen) workflow(ctx context.Context, db *postgres.DB) error {
	q := db.Querier()
	for i := 0; i < 24; i++ {
		status := 1
		switch {
		case i >= 8 && i < 18:
			status = 2
		case i >= 18:
			status = 3
		}
		at := g.ago(60)
		row := map[string]any{"id": fmt.Sprintf("req-%03d", i+1), "secret_id": fmt.Sprintf("sec-%04d", 30+i), "requested_by_user_id": g.user(5 + i%10).id, "status": status, "requested_at": at.Format(time.RFC3339), "reason": "maintenance window"}
		if status != 1 {
			row["resolved_at"], row["resolved_by_user_id"] = at.Add(time.Hour).Format(time.RFC3339), g.user(0).id
		}
		if i%7 == 6 {
			row["kind"], row["folder_id"], row["dest_parent_id"], row["folder_name"], row["dest_parent_name"] = 1, "folder-lab-doors", "folder-personal-02", "Doors", "Personal"
		}
		if err := g.insert(ctx, q, schema.Workflow, "approval_requests", row); err != nil {
			return err
		}
	}
	for i := 0; i < 30; i++ {
		row := map[string]any{"id": fmt.Sprintf("cmt-%03d", i+1), "request_id": fmt.Sprintf("req-%03d", i%24+1), "author_user_id": g.user(i % 6).id, "body": "Synthetic comment", "created_at": g.ago(30).Format(time.RFC3339)}
		if err := g.insert(ctx, q, schema.Workflow, "approval_comments", row); err != nil {
			return err
		}
	}
	for i := 0; i < 12; i++ {
		issued := g.ago(10)
		row := map[string]any{"id": fmt.Sprintf("lease-%03d", i+1), "secret_id": fmt.Sprintf("sec-%04d", 60+i), "user_id": g.user(3 + i%8).id, "issued_at": issued.Format(time.RFC3339), "expires_at": issued.Add(8 * time.Hour).Format(time.RFC3339), "returned": i >= 5}
		if i < 5 {
			row["expires_at"] = g.now.Add(4 * time.Hour).Format(time.RFC3339)
		}
		if err := g.insert(ctx, q, schema.Workflow, "leases", row); err != nil {
			return err
		}
	}
	return nil
}

func (g *gen) audit(ctx context.Context, db *postgres.DB) error {
	q := db.Querier()
	start := g.now.Add(-time.Duration(g.opts.AuditRecords) * time.Minute)
	prev := ""
	for i := 0; i < g.opts.AuditRecords; i++ {
		u := g.user(i)
		r := chain.Record{
			Seq: uint64(i + 1), Tier: int32(1 + i%2), Action: actions[i%len(actions)], ActorUserID: u.id,
			Subject: fmt.Sprintf("sec-%04d", 1+i%g.opts.Secrets), Sensitive: i%2 == 0,
			Attributes: map[string]string{}, OccurredAt: start.Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano), PrevHash: prev,
		}
		if i%3 == 0 {
			r.Attributes["outcome"] = "ok"
		}
		if i%11 == 0 {
			r.Attributes["ip"] = "192.0.2." + fmt.Sprint(1+i%200)
			r.GroupID = fmt.Sprintf("grp-%02d", 1+i%len(groupNames))
		}
		r.Hash = chain.Hash(r)
		prev = r.Hash
		attrs, err := json.Marshal(r.Attributes)
		if err != nil {
			return err
		}
		row := map[string]any{"seq": int64(r.Seq), // #nosec G115 -- seq counts the records written here
			"tier": r.Tier, "action": r.Action, "actor_user_id": r.ActorUserID, "subject": r.Subject, "group_id": r.GroupID, "sensitive": r.Sensitive, "attributes": attrs, "occurred_at": r.OccurredAt, "prev_hash": r.PrevHash, "hash": r.Hash}
		if err := g.insert(ctx, q, schema.Audit, "audit_records", row); err != nil {
			return err
		}
	}
	return nil
}

// Fingerprint is a short, non-reversible tag for a key, for logs.
func Fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}
