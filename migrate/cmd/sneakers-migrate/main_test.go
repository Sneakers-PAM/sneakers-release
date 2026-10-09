// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
)

func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestHelpAndVersion(t *testing.T) {
	if code, out, _ := runArgs(t); code != exitOK || !strings.Contains(out, "export") || !strings.Contains(out, "verify") {
		t.Fatalf("help: %d %q", code, out)
	}
	code, out, _ := runArgs(t, "version")
	if code != exitOK || !strings.Contains(out, "bundle format sneakers-migrate-bundle 1.1") || !strings.Contains(out, "source profile original-v1") {
		t.Fatalf("version: %d %q", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"export", "--nope"},
		{"export", "--out", "x.age"},
		{"export", "--out", "x.age", "--recipient", "age1notakey"},
		{"import", "--bundle", "b"},
		{"keygen"},
	} {
		if code, _, stderr := runArgs(t, args...); code != exitUsage {
			t.Fatalf("%v: exit %d (%s), want %d", args, code, stderr, exitUsage)
		}
	}
}

// Outside rehearsal mode an import needs the owner's mapping file, whatever
// else it is asked to do.
func TestImportOutsideRehearsalNeedsAMapping(t *testing.T) {
	for _, args := range [][]string{
		{"import", "--bundle", "b", "--identity", "i"},
		{"import", "--bundle", "b", "--identity", "i", "--wipe-target"},
		{"import", "--bundle", "b", "--identity", "i", "--owner-email", "owner@example.org"},
	} {
		if code, _, _ := runArgs(t, args...); code != exitRefused {
			t.Fatalf("%v: exit %d, want %d", args, code, exitRefused)
		}
	}
}

func TestKeygenThenABundleThatWontOpen(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "import.key")
	code, out, _ := runArgs(t, "keygen", "--out", id)
	if code != exitOK || !strings.HasPrefix(out, "age1") {
		t.Fatalf("keygen: %d %q", code, out)
	}
	st, err := os.Stat(id)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("identity file mode = %v, %v", st.Mode(), err)
	}
	if code, _, _ := runArgs(t, "keygen", "--out", id); code != exitError {
		t.Fatalf("keygen over an existing file: exit %d, want %d", code, exitError)
	}
	junk := filepath.Join(dir, "bundle.age")
	if err := os.WriteFile(junk, []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TARGET_IDENTITY_DSN", "postgres://db.example.org/identity")
	t.Setenv("TARGET_VAULT_DSN", "postgres://db.example.org/vault")
	t.Setenv("TARGET_WORKFLOW_DSN", "postgres://db.example.org/workflow")
	t.Setenv("TARGET_AUDIT_DSN", "postgres://db.example.org/audit")
	t.Setenv("TARGET_KRATOS_ADMIN_URL", "http://kratos.example.org")
	t.Setenv("TARGET_VAULT_ADDR", "vault.example.org:9091")
	t.Setenv("TARGET_AUDIT_ADDR", "audit.example.org:9093")
	if code, _, stderr := runArgs(t, "verify", "--bundle", junk, "--identity", id); code != exitBundle {
		t.Fatalf("junk bundle: exit %d (%s), want %d", code, stderr, exitBundle)
	}
}

func TestExitCodeRanges(t *testing.T) {
	for c, want := range map[int]int{codes.SourceVersion: exitRefused, codes.TargetNotEmpty: exitRefused, codes.VerifyMismatch: exitVerify, codes.BundleKey: exitBundle} {
		if got := exitCode(codes.Wrap(c, errors.New("x"))); got != want {
			t.Fatalf("code %d: exit %d, want %d", c, got, want)
		}
	}
	if exitCode(errors.New("plain")) != exitError {
		t.Fatal("an uncoded error is a general error")
	}
}
