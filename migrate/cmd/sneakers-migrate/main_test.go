// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
)

func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestHelpAndVersion(t *testing.T) {
	if code, out, _ := runArgs(t); code != exitOK || !strings.Contains(out, "export") || !strings.Contains(out, "verify") || !strings.Contains(out, "wait") {
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
		{"wait"},
		{"wait", "--dns", "kubernetes.default.svc.cluster.local"},
		{"wait", "--dns", "kubernetes.default.svc.cluster.local", "--tcp", "not-a-host-port"},
		{"wait", "--dns", "kubernetes.default.svc.cluster.local", "--tcp", "svc.example.org:9090", "--every", "0s"},
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

func TestWaitExitsOKOnceEveryTargetAnswers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code := run(ctx, []string{"wait", "--dns", "localhost", "--tcp", ln.Addr().String(), "--every", "10ms"}, &out, &errb)
	if code != exitOK {
		t.Fatalf("wait: exit %d (%s)", code, errb.String())
	}
}

func TestOutputFileCopiesTheRunAndItsExitCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.txt")
	var out, errb bytes.Buffer
	stdout, stderr, done, err := outputFile(path, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	code := run(context.Background(), []string{"import", "--bundle", "b", "--identity", "i"}, stdout, stderr)
	done(code)
	got, _ := os.ReadFile(path)
	exit, _ := os.ReadFile(path + ".exit")
	if code != exitRefused || !strings.Contains(string(got), "mapping file") || strings.TrimSpace(string(exit)) != "3" || !strings.Contains(errb.String(), "mapping file") {
		t.Fatalf("code %d, file %q, exit %q", code, got, exit)
	}
}
