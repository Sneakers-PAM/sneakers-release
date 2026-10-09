// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package schema names the tables sneakers-migrate moves: the source profile
// it knows how to read, the order tables are written in, and what each table
// needs on the way (sealed values, seed rows, transient rows left behind).
package schema

// Service is one database.
type Service string

// The databases, in import order.
const (
	Identity Service = "identity"
	Vault    Service = "vault"
	Workflow Service = "workflow"
	Audit    Service = "audit"
)

// Services lists the databases in import order.
var Services = []Service{Identity, Vault, Workflow, Audit}

// Kind says how a table moves.
type Kind int

const (
	// Copy rows as they are (after the mapping).
	Copy Kind = iota
	// Sealed rows carry a vault envelope: opened at export, re-sealed by the
	// target vault at import.
	Sealed
	// Seed rows the target vault may install itself; the source rows win.
	Seed
	// Transient rows (pending codes, ceremony state) are left behind.
	Transient
	// Replaced rows are the source's key material; the target keeps its own.
	Replaced
)

// Table is one table of one service.
type Table struct {
	Service Service
	Name    string
	Key     []string // primary key columns, also the export order
	Kind    Kind
	// UserData tables decide whether a target is empty.
	UserData bool
}

// Stream is the table's bundle stream name.
func (t Table) Stream() string { return string(t.Service) + "." + t.Name }

// Profile is a source version this tool reads: the golang-migrate version of
// each database.
type Profile struct {
	Name     string
	Versions map[Service]int64
}

// SourceProfile is the original system at its frozen main.
var SourceProfile = Profile{
	Name:     "original-v1",
	Versions: map[Service]int64{Identity: 10, Vault: 6, Workflow: 1, Audit: 1},
}

// TargetVersion is the migration version of every target baseline.
const TargetVersion int64 = 1

// TargetVersions are the target migration versions this tool writes, per
// service: the baseline and the migrations after it whose new columns it
// fills (identity 2: a personal token's client kind; vault 2: a break-glass
// event's session; vault 3: a secret's place in its folder).
var TargetVersions = map[Service][]int64{
	Identity: {1, 2},
	Vault:    {1, 2, 3},
	Workflow: {1},
	Audit:    {1},
}

// WritesTarget reports whether the tool writes a service at this version.
func WritesTarget(s Service, v int64) bool {
	for _, x := range TargetVersions[s] {
		if x == v {
			return true
		}
	}
	return false
}

// VersionTable is the golang-migrate version table of a service's own
// migrations. The workflow database also holds the go-saga engine's tables,
// whose version is in schema_migrations, so the workflow service keeps its
// own in workflow_schema_migrations (in the original system and the target).
func VersionTable(s Service) string {
	if s == Workflow {
		return "workflow_schema_migrations"
	}
	return "schema_migrations"
}

// Tables lists every table, each service's in insert (dependency) order.
var Tables = []Table{
	{Service: Identity, Name: "users", Key: []string{"id"}, UserData: true},
	{Service: Identity, Name: "groups", Key: []string{"id"}, UserData: true},
	{Service: Identity, Name: "group_membership", Key: []string{"user_id", "group_id"}},
	{Service: Identity, Name: "service_accounts", Key: []string{"id"}, UserData: true},
	{Service: Identity, Name: "api_tokens", Key: []string{"id"}},
	{Service: Identity, Name: "user_tokens", Key: []string{"id"}},
	{Service: Identity, Name: "user_totp", Key: []string{"user_id"}},
	{Service: Identity, Name: "user_webauthn_credentials", Key: []string{"credential_id"}},
	{Service: Identity, Name: "user_email_otp", Key: []string{"id"}, Kind: Transient},
	{Service: Identity, Name: "webauthn_sessions", Key: []string{"session_id"}, Kind: Transient},

	{Service: Vault, Name: "secret_types", Key: []string{"id"}, Kind: Seed},
	{Service: Vault, Name: "extension_catalog", Key: []string{"id"}, Kind: Seed},
	{Service: Vault, Name: "password_policies", Key: []string{"id"}, Kind: Seed},
	{Service: Vault, Name: "security_settings", Key: []string{"id"}, Kind: Seed},
	{Service: Vault, Name: "connections", Key: []string{"id"}, Kind: Seed},
	{Service: Vault, Name: "targets", Key: []string{"id"}, UserData: true},
	{Service: Vault, Name: "target_raci_rules", Key: []string{"id"}},
	{Service: Vault, Name: "folders", Key: []string{"id"}, UserData: true},
	{Service: Vault, Name: "folder_rules", Key: []string{"id"}},
	{Service: Vault, Name: "raci_rules", Key: []string{"id"}},
	{Service: Vault, Name: "secrets", Key: []string{"id"}, UserData: true},
	{Service: Vault, Name: "secret_records", Key: []string{"secret_id"}, Kind: Sealed},
	{Service: Vault, Name: "secret_versions", Key: []string{"secret_id", "version_no"}, Kind: Sealed, UserData: true},
	{Service: Vault, Name: "rotation_schedule", Key: []string{"secret_id"}},
	{Service: Vault, Name: "heartbeat_schedule", Key: []string{"secret_id"}},
	{Service: Vault, Name: "secret_uses", Key: []string{"id"}},
	{Service: Vault, Name: "secret_use_grants", Key: []string{"id"}},
	{Service: Vault, Name: "break_glass_events", Key: []string{"id"}},
	{Service: Vault, Name: "kek_keyring", Key: []string{"ref"}, Kind: Replaced},

	{Service: Workflow, Name: "approval_requests", Key: []string{"id"}, UserData: true},
	{Service: Workflow, Name: "approval_comments", Key: []string{"id"}},
	{Service: Workflow, Name: "leases", Key: []string{"id"}, UserData: true},

	{Service: Audit, Name: "audit_records", Key: []string{"seq"}, UserData: true},
}

// TargetOnly are tables the target has and the source doesn't. They stay
// empty after import and are cleared by a rehearsal wipe.
var TargetOnly = []Table{
	{Service: Vault, Name: "target_ssh_host_keys", Key: []string{"target_id", "ordinal"}},
	{Service: Vault, Name: "break_glass_sessions", Key: []string{"id"}},
}

// Of returns a service's tables in insert order.
func Of(s Service) []Table {
	var out []Table
	for _, t := range Tables {
		if t.Service == s {
			out = append(out, t)
		}
	}
	return out
}

// Carried reports whether a table's rows travel in the bundle.
func (t Table) Carried() bool { return t.Kind != Transient && t.Kind != Replaced }

// Lookup returns a table by stream name.
func Lookup(stream string) (Table, bool) {
	for _, t := range Tables {
		if t.Stream() == stream {
			return t, true
		}
	}
	return Table{}, false
}

// KratosStream carries the Kratos identities.
const KratosStream = "kratos.identities"

// Category is one thing the parity report counts, and the stream it lives in.
type Category struct {
	Name   string
	Stream string
}

// ParityCategories are counted in the source, the bundle and the target.
var ParityCategories = []Category{
	{Name: "folders", Stream: "vault.folders"},
	{Name: "secrets", Stream: "vault.secrets"},
	{Name: "types", Stream: "vault.secret_types"},
	{Name: "users", Stream: "identity.users"},
	{Name: "targets", Stream: "vault.targets"},
	{Name: "connections", Stream: "vault.connections"},
}
