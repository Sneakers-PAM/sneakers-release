// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
)

func env(m map[string]string) Getenv { return func(k string) string { return m[k] } }

func full(prefix string) map[string]string {
	m := map[string]string{}
	for _, s := range schema.Services {
		m[prefix+"_"+strings.ToUpper(string(s))+"_DSN"] = "postgres://db.example.org/" + string(s)
	}
	return m
}

func TestLoadSource(t *testing.T) {
	m := full("SOURCE")
	m["SOURCE_KRATOS_ADMIN_URL"] = "http://kratos-admin"
	m["SOURCE_VAULT_ROOT_KEK"] = "a2V5"
	s, err := LoadSource(env(m))
	if err != nil || s.DSN[schema.Vault] != "postgres://db.example.org/vault" {
		t.Fatalf("LoadSource = %+v, %v", s, err)
	}
	delete(m, "SOURCE_AUDIT_DSN")
	delete(m, "SOURCE_VAULT_ROOT_KEK")
	_, err = LoadSource(env(m))
	if err == nil || !strings.Contains(err.Error(), "SOURCE_AUDIT_DSN") || !strings.Contains(err.Error(), "SOURCE_VAULT_ROOT_KEK") {
		t.Fatalf("missing variables not named: %v", err)
	}
}

func TestLoadTarget(t *testing.T) {
	m := full("TARGET")
	m["TARGET_KRATOS_ADMIN_URL"], m["TARGET_VAULT_ADDR"], m["TARGET_AUDIT_ADDR"] = "http://k", "vault:9091", "audit:9093"
	tg, err := LoadTarget(env(m))
	if err != nil || tg.Principal != DefaultPrincipal {
		t.Fatalf("LoadTarget = %+v, %v", tg, err)
	}
	m["MIGRATE_PRINCIPAL"] = "user-1"
	if _, err := LoadTarget(env(m)); err == nil {
		t.Fatal("a non-system principal must be refused")
	}
	m["MIGRATE_PRINCIPAL"] = "system:migrate-qa"
	delete(m, "TARGET_VAULT_ADDR")
	if _, err := LoadTarget(env(m)); err == nil || !strings.Contains(err.Error(), "TARGET_VAULT_ADDR") {
		t.Fatalf("missing vault address not named: %v", err)
	}
}
