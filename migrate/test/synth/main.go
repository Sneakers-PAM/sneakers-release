// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command synth stands up the synthetic source for a rehearsal: it applies the
// source schema to four empty databases and seeds them, and the source Kratos,
// with an invented dataset sealed under freshly generated keys. The keys are
// written to a 0600 file for the export step. Never point it at a real system.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/synth"
	"github.com/spf13/cobra"
)

type options struct {
	schemaDir string
	keysOut   string
	summary   string
	opts      synth.Options
}

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "synth:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:   "synth",
		Short: "Stand up and seed the synthetic source for a sneakers-migrate rehearsal",
		Long: `Applies the source schema to the databases named by SOURCE_IDENTITY_DSN,
SOURCE_VAULT_DSN, SOURCE_WORKFLOW_DSN and SOURCE_AUDIT_DSN, then seeds them and
the Kratos admin API at SOURCE_KRATOS_ADMIN_URL with invented data.`,
		SilenceUsage: true,
		RunE:         func(cmd *cobra.Command, _ []string) error { return o.run(cmd.Context()) },
	}
	cmd.CompletionOptions.DisableDefaultCmd = true
	f := cmd.Flags()
	f.StringVarP(&o.schemaDir, "schema-dir", "s", "migrate/testdata/source-schema", "directory with identity/, vault/, workflow/ and audit/ migration folders")
	f.StringVarP(&o.keysOut, "keys-out", "k", "", "file to write the generated source keys to (0600, required)")
	f.StringVarP(&o.summary, "summary-out", "o", "", "file to write the row counts to (JSON)")
	f.IntVarP(&o.opts.Users, "users", "u", 30, "users to create")
	f.IntVarP(&o.opts.Secrets, "secrets", "n", 200, "secrets to create")
	f.IntVarP(&o.opts.AuditRecords, "audit-records", "a", 1000, "audit records to chain")
	f.StringVarP(&o.opts.OwnerEmail, "owner-email", "e", "owner@example.org", "the root user's address")
	_ = cmd.MarkFlagRequired("keys-out")
	return cmd
}

func (o *options) run(ctx context.Context) error {
	dsn := map[schema.Service]string{}
	dirs := map[schema.Service]string{}
	for _, s := range schema.Services {
		v := os.Getenv("SOURCE_" + upper(string(s)) + "_DSN")
		if v == "" {
			return fmt.Errorf("SOURCE_%s_DSN is not set", upper(string(s)))
		}
		dsn[s] = v
		dirs[s] = filepath.Join(o.schemaDir, string(s))
	}
	kurl := os.Getenv("SOURCE_KRATOS_ADMIN_URL")
	if kurl == "" {
		return fmt.Errorf("SOURCE_KRATOS_ADMIN_URL is not set")
	}
	if err := synth.Migrate(dsn, dirs); err != nil {
		return err
	}
	dbs := map[schema.Service]*postgres.DB{}
	for s, v := range dsn {
		db, err := postgres.New(ctx, v)
		if err != nil {
			return fmt.Errorf("connect %s: %w", s, err)
		}
		defer db.Close()
		dbs[s] = db
	}
	keys, err := synth.NewKeys()
	if err != nil {
		return err
	}
	sum, err := synth.Seed(ctx, dbs, kratos.New(kurl), keys, o.opts)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(map[string]string{
		"SOURCE_VAULT_ROOT_KEK": keys.RootKeyB64(), "SOURCE_DEV_KEK_SEED": keys.DevSeed, "SOURCE_TOTP_ENC_KEY": keys.TOTPKeyB64(),
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.keysOut, raw, 0o600); err != nil { // #nosec G703 -- the operator names the output
		return err
	}
	out, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return err
	}
	if o.summary != "" {
		if err := os.WriteFile(o.summary, out, 0o600); err != nil { // #nosec G703 -- the operator names the output
			return err
		}
	}
	fmt.Printf("seeded %d Kratos identities and %d tables (root key %s)\n", sum.Kratos, len(sum.Rows), synth.Fingerprint(keys.RootKey))
	return nil
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
