// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package testenv builds the databases the integration tests run against: a
// synthetic source in the source profile's schema, and an empty target in the
// layout of the Sneakers-PAM baselines. Tests skip when MIGRATE_TEST_PG is
// unset.
package testenv

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos/kratostest"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/source"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/synth"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/testpg"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/totpcipher"
)

// SourceSchema is the source-schema fixture directory.
func SourceSchema() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "source-schema")
}

// Source is a seeded synthetic source.
type Source struct {
	Config  source.Config
	Kratos  *kratostest.Server
	Summary *synth.Summary
	DB      map[schema.Service]*postgres.DB
	Keys    synth.Keys
}

func open(t *testing.T, dsn map[schema.Service]string) map[schema.Service]*postgres.DB {
	t.Helper()
	dbs := map[schema.Service]*postgres.DB{}
	for s, v := range dsn {
		db, err := postgres.New(context.Background(), v)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		dbs[s] = db
	}
	return dbs
}

func migrated(t *testing.T, prefix string) map[schema.Service]string {
	t.Helper()
	dsn := map[schema.Service]string{}
	dirs := map[schema.Service]string{}
	for _, s := range schema.Services {
		dsn[s] = testpg.DSN(t, prefix+"_"+string(s))
		dirs[s] = filepath.Join(SourceSchema(), string(s))
	}
	if err := synth.Migrate(dsn, dirs); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return dsn
}

// NewSource seeds a synthetic source on throwaway databases.
func NewSource(t *testing.T, opts synth.Options) *Source {
	t.Helper()
	dsn := migrated(t, "src")
	dbs := open(t, dsn)
	kf := kratostest.New()
	t.Cleanup(kf.Close)
	keys, err := synth.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	sum, err := synth.Seed(context.Background(), dbs, kratos.New(kf.URL), keys, opts)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	tc, err := totpcipher.New(keys.TOTPKey)
	if err != nil {
		t.Fatal(err)
	}
	return &Source{
		Config: source.Config{DSN: dsn, RootKey: keys.RootKey, DevSeed: keys.DevSeed, TOTP: tc, SampleMax: 5},
		Kratos: kf, Summary: sum, DB: dbs, Keys: keys,
	}
}

// toTarget turns the source layout into the target baselines' layout: the
// two schema differences sneakers-migrate maps, and baseline version 1.
var toTarget = map[schema.Service][]string{
	schema.Identity: {
		"ALTER TABLE public.users RENAME COLUMN keycloak_subject TO subject",
		"ALTER INDEX public.users_keycloak_subject_key RENAME TO users_subject_key",
	},
	schema.Vault: {
		`CREATE TABLE public.target_ssh_host_keys (target_id text NOT NULL, ordinal integer NOT NULL, public_key text NOT NULL, fingerprint text NOT NULL, PRIMARY KEY (target_id, ordinal))`,
	},
}

// NewTarget returns empty target databases in the baseline layout.
func NewTarget(t *testing.T) (map[schema.Service]string, map[schema.Service]*postgres.DB) {
	t.Helper()
	dsn := migrated(t, "tgt")
	dbs := open(t, dsn)
	ctx := context.Background()
	for _, s := range schema.Services {
		for _, sql := range append(toTarget[s], "UPDATE public."+schema.VersionTable(s)+" SET version = 1") {
			if _, err := dbs[s].Querier().Exec(ctx, sql); err != nil {
				t.Fatalf("%s: %s: %v", s, sql, err)
			}
		}
	}
	return dsn, dbs
}
