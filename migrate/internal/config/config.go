// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package config reads sneakers-migrate's connection settings and keys from
// the environment. Secrets are only ever taken from the environment (a Job
// fills it from Kubernetes Secrets), never from flags, so they don't show in
// a process list.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
)

// Getenv reads one variable.
type Getenv func(string) string

// DefaultPrincipal is the workload principal the tool presents to the vault
// (VAULT_IMPORT_PRINCIPALS) and the actor its audit entries carry.
const DefaultPrincipal = "system:sneakers-migrate"

// Source is the export side.
type Source struct {
	DSN            map[schema.Service]string
	KratosAdminURL string
	RootKey        string
	DevSeed        string
	TOTPKey        string
}

// Target is the import and verify side.
type Target struct {
	DSN            map[schema.Service]string
	KratosAdminURL string
	VaultAddr      string
	AuditAddr      string
	TOTPKey        string
	Principal      string
	TokenFile      string
}

func dsns(get Getenv, prefix string) (map[schema.Service]string, []string) {
	out := map[schema.Service]string{}
	var missing []string
	for _, s := range schema.Services {
		name := prefix + "_" + strings.ToUpper(string(s)) + "_DSN"
		v := get(name)
		if v == "" {
			missing = append(missing, name)
		}
		out[s] = v
	}
	return out, missing
}

func need(missing []string) error {
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("missing environment: %s", strings.Join(missing, ", "))
}

// LoadSource reads SOURCE_*: the four database DSNs, the Kratos admin URL,
// the vault root key, and the optional dev seed and TOTP key.
func LoadSource(get Getenv) (Source, error) {
	s := Source{KratosAdminURL: get("SOURCE_KRATOS_ADMIN_URL"), RootKey: get("SOURCE_VAULT_ROOT_KEK"), DevSeed: get("SOURCE_DEV_KEK_SEED"), TOTPKey: get("SOURCE_TOTP_ENC_KEY")}
	var missing []string
	s.DSN, missing = dsns(get, "SOURCE")
	if s.KratosAdminURL == "" {
		missing = append(missing, "SOURCE_KRATOS_ADMIN_URL")
	}
	if s.RootKey == "" {
		missing = append(missing, "SOURCE_VAULT_ROOT_KEK")
	}
	return s, need(missing)
}

// LoadTarget reads TARGET_*: the four database DSNs, the Kratos admin URL,
// the vault and audit gRPC addresses, the identity TOTP key, and
// MIGRATE_PRINCIPAL and WORKLOAD_TOKEN_FILE.
func LoadTarget(get Getenv) (Target, error) {
	t := Target{
		KratosAdminURL: get("TARGET_KRATOS_ADMIN_URL"), VaultAddr: get("TARGET_VAULT_ADDR"), AuditAddr: get("TARGET_AUDIT_ADDR"),
		TOTPKey: get("TARGET_TOTP_ENC_KEY"), Principal: get("MIGRATE_PRINCIPAL"), TokenFile: get("WORKLOAD_TOKEN_FILE"),
	}
	var missing []string
	t.DSN, missing = dsns(get, "TARGET")
	for name, v := range map[string]string{"TARGET_KRATOS_ADMIN_URL": t.KratosAdminURL, "TARGET_VAULT_ADDR": t.VaultAddr, "TARGET_AUDIT_ADDR": t.AuditAddr} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if t.Principal == "" {
		t.Principal = DefaultPrincipal
	}
	if !strings.HasPrefix(t.Principal, "system:") || len(t.Principal) == len("system:") {
		return t, errors.New("MIGRATE_PRINCIPAL must be system:<name>")
	}
	return t, need(missing)
}
