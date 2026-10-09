// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package report is the record of an import or a verify run: ids, counts and
// results only. It never carries a value, a hash of a value or a token, so a
// report can be kept after the run's data is wiped.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
)

// Count is one table's rows in the bundle and on the target.
type Count struct {
	Table  string `json:"table"`
	Bundle int    `json:"bundle"`
	// Expected is the bundle count after the mapping (closing an approval
	// adds a comment).
	Expected int `json:"expected"`
	Target   int `json:"target"`
}

// Setting is one imported security setting next to the target's default.
type Setting struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Imported string `json:"imported"`
	Default  string `json:"default"`
}

// Security lists the imported security settings and warns on each one the
// target now enforces in a way that restricts something.
type Security struct {
	Settings []Setting `json:"settings"`
	Warnings []string  `json:"warnings"`
}

// Import is the record of an import.
type Import struct {
	BundleID           string              `json:"bundle_id"`
	Mode               string              `json:"mode"`
	StartedAt          string              `json:"started_at"`
	FinishedAt         string              `json:"finished_at"`
	Services           map[string]string   `json:"services"`
	Tables             []Count             `json:"tables"`
	Security           Security            `json:"security"`
	KratosIdentities   int                 `json:"kratos_identities"`
	KratosCreated      int                 `json:"kratos_created"`
	KratosReused       int                 `json:"kratos_reused"`
	VersionSamples     int                 `json:"older_version_samples_matched"`
	Closed             map[string]int      `json:"closed_by_migration"`
	SSHTargetsToPin    []string            `json:"ssh_targets_needing_host_key_pins"`
	UsersWithoutSignIn []string            `json:"users_without_sign_in_identity"`
	NotCarried         []bundle.NotCarried `json:"not_carried"`
	AuditEntries       int                 `json:"migration_audit_entries"`
	OwnerPasswordSet   bool                `json:"owner_password_set"`
	Wiped              bool                `json:"target_wiped"`
	Notes              []string            `json:"notes,omitempty"`
	CurrentOnly        bool                `json:"current_only"`
	SignInReset        bool                `json:"sign_in_reset"`
	Remap              *mapping.RemapStats `json:"mapping,omitempty"`
	Parity             []Parity            `json:"parity"`
}

// Parity is one category counted at every step: the source, the bundle,
// what the mapping dropped and created, what the target should hold and
// what it holds.
type Parity struct {
	Name     string `json:"name"`
	Source   int    `json:"source"`
	Bundle   int    `json:"bundle"`
	Dropped  int    `json:"dropped"`
	Created  int    `json:"created"`
	Expected int    `json:"expected"`
	Target   int    `json:"target"`
	OK       bool   `json:"ok"`
}

// ParityText writes a parity table.
func ParityText(pr *Printer, ps []Parity) {
	if len(ps) == 0 {
		return
	}
	pr.ln("parity (source / dropped / created / expected / target):")
	for _, p := range ps {
		mark := "ok"
		if !p.OK {
			mark = "MISMATCH"
		}
		pr.f("  %-12s %6d %6d %6d %6d %6d  %s\n", p.Name, p.Source, p.Dropped, p.Created, p.Expected, p.Target, mark)
	}
}

// Check is one verify check.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Verify is the record of a verify run.
type Verify struct {
	BundleID string   `json:"bundle_id"`
	At       string   `json:"at"`
	OK       bool     `json:"ok"`
	Checks   []Check  `json:"checks"`
	Counts   []Count  `json:"counts"`
	Parity   []Parity `json:"parity"`
	Tokens   Tokens   `json:"personal_tokens"`
	Failures []string `json:"failures,omitempty"`
}

// Tokens is the personal-token check, by token id only.
type Tokens struct {
	OK      int      `json:"ok"`
	Skipped int      `json:"skipped"`
	Failing []string `json:"failing,omitempty"`
}

// Add records a check.
func (v *Verify) Add(name string, ok bool, detail string) {
	v.Checks = append(v.Checks, Check{Name: name, OK: ok, Detail: detail})
}

// Finish sets OK from the checks.
func (v *Verify) Finish() {
	v.OK = len(v.Checks) > 0
	for _, c := range v.Checks {
		v.OK = v.OK && c.OK
	}
}

// WriteFile writes a report as JSON (0600).
func WriteFile(path string, r any) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// Printer writes formatted lines and keeps the first write error.
type Printer struct {
	w   io.Writer
	err error
}

// NewPrinter wraps w.
func NewPrinter(w io.Writer) *Printer { return &Printer{w: w} }

func (p *Printer) f(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

func (p *Printer) ln(a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.w, a...)
	}
}

// F writes a formatted string.
func (p *Printer) F(format string, a ...any) { p.f(format, a...) }

// Err is the first write error.
func (p *Printer) Err() error { return p.err }

// Text writes an import report for a person to read.
func (r *Import) Text(w io.Writer) error {
	pr := NewPrinter(w)
	pr.f("import %s (%s): %s to %s\n", r.BundleID, r.Mode, r.StartedAt, r.FinishedAt)
	svcs := make([]string, 0, len(r.Services))
	for s := range r.Services {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	for _, s := range svcs {
		pr.f("  %-9s %s\n", s, r.Services[s])
	}
	counts(pr, r.Tables)
	pr.f("kratos identities: %d (%d created, %d already there)\n", r.KratosIdentities, r.KratosCreated, r.KratosReused)
	pr.f("older-version samples matched before sealing: %d\n", r.VersionSamples)
	if len(r.Closed) > 0 {
		keys := make([]string, 0, len(r.Closed))
		for k := range r.Closed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pr.ln("closed by migration:")
		for _, k := range keys {
			pr.f("  %-18s %d\n", k, r.Closed[k])
		}
	}
	list(pr, "SSH targets needing host-key pins", r.SSHTargetsToPin)
	list(pr, "users without a sign-in identity", r.UsersWithoutSignIn)
	if len(r.NotCarried) > 0 {
		pr.ln("not carried:")
		for _, n := range r.NotCarried {
			pr.f("  %-30s %5d  %s\n", n.Name, n.Rows, n.Reason)
		}
	}
	if len(r.Security.Settings) > 0 {
		pr.ln("security settings (imported / new default):")
		for _, st := range r.Security.Settings {
			pr.f("  %-38s %s / %s\n", st.Name, st.Imported, st.Default)
		}
	}
	for _, w := range r.Security.Warnings {
		pr.ln("warning:", w)
	}
	if r.CurrentOnly {
		pr.ln("secret history: current values only")
	}
	if r.SignInReset {
		pr.ln("sign-in: reset; every user sets a new password and enrols a second factor")
	}
	if m := r.Remap; m != nil {
		pr.f("mapping %s: folders %d moved, %d created, %d dropped; secrets %d moved, %d renamed, %d retyped, %d dropped, %d not listed (kept)\n",
			m.MappingSHA256, m.FoldersMoved, m.FoldersCreated, m.FoldersDropped, m.SecretsMoved, m.SecretsRenamed, m.SecretsRetyped, m.SecretsDropped, m.SecretsKept)
		for _, w := range m.Warnings {
			pr.ln("mapping warning:", w)
		}
	}
	ParityText(pr, r.Parity)
	pr.f("migration audit entries appended: %d\n", r.AuditEntries)
	for _, n := range r.Notes {
		pr.ln("note:", n)
	}
	return pr.err
}

// Text writes a verify report for a person to read.
func (v *Verify) Text(w io.Writer) error {
	pr := NewPrinter(w)
	status := "PASSED"
	if !v.OK {
		status = "FAILED"
	}
	pr.f("verify %s at %s: %s\n", v.BundleID, v.At, status)
	counts(pr, v.Counts)
	ParityText(pr, v.Parity)
	for _, c := range v.Checks {
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
		}
		pr.f("  [%s] %-22s %s\n", mark, c.Name, c.Detail)
	}
	for _, f := range v.Failures {
		pr.ln("  failure:", f)
	}
	return pr.err
}

func counts(pr *Printer, cs []Count) {
	if len(cs) == 0 {
		return
	}
	pr.f("  %-36s %8s %8s %8s\n", "table", "bundle", "expected", "target")
	for _, c := range cs {
		mark := ""
		if c.Expected != c.Target {
			mark = "  MISMATCH"
		}
		pr.f("  %-36s %8d %8d %8d%s\n", c.Table, c.Bundle, c.Expected, c.Target, mark)
	}
}

func list(pr *Printer, title string, ids []string) {
	if len(ids) == 0 {
		return
	}
	pr.f("%s (%d): %s\n", title, len(ids), strings.Join(ids, ", "))
}
