// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package testpg gives integration tests throwaway Postgres databases on the
// server named by MIGRATE_TEST_PG (an admin DSN). Tests that need it skip when
// it is unset.
package testpg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
)

// DSN creates a fresh database and returns its DSN; the database is dropped
// when the test ends.
func DSN(t *testing.T, prefix string) string {
	t.Helper()
	admin := os.Getenv("MIGRATE_TEST_PG")
	if admin == "" {
		t.Skip("MIGRATE_TEST_PG is not set; skipping the Postgres integration test")
	}
	ctx := context.Background()
	db, err := postgres.New(ctx, admin)
	if err != nil {
		t.Fatalf("connect MIGRATE_TEST_PG: %v", err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := prefix + "_" + hex.EncodeToString(b)
	if _, err := db.Querier().Exec(ctx, "CREATE DATABASE "+name); err != nil {
		db.Close()
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Querier().Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		db.Close()
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse MIGRATE_TEST_PG: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}
