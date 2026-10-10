// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"errors"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/config"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/target"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/totpcipher"
	"github.com/spf13/cobra"
)

type importOptions struct {
	bundle     string
	identity   string
	rehearsal  bool
	wipe       bool
	ownerEmail string
	report     string
	mapping    string
}

// ImportCmd loads a bundle into a fresh target install.
func ImportCmd(e env, lg logFn) *cobra.Command {
	o := &importOptions{}
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Load a bundle into a fresh Sneakers-PAM install",
		Long: `import decrypts the bundle in memory, maps the source layout to the Sneakers-PAM
baselines, imports the Kratos identities with their password hashes, has the
target vault re-seal every secret version, writes each service database in one
transaction, inserts the audit chain as it is and appends the migration's own
audit entries. It refuses a target that holds other data.

--mapping applies the owner's approved mapping file (folders, names and types
re-mapped, retired items dropped); outside rehearsal mode it is required.
Every import prints a parity table (folders, secrets, types, users, targets,
connections) and fails if the target doesn't hold what the source, less the
mapping's drops, held.

--rehearsal imports with KEK rotation off. --wipe-target empties the target
first: any target in rehearsal mode, otherwise only one an earlier import
filled (a re-import). --owner-email gives one account a one-time password: in
rehearsal mode, or for a bundle exported with --reset-sign-in. Restart the
vault after an import.

Environment: TARGET_IDENTITY_DSN, TARGET_VAULT_DSN, TARGET_WORKFLOW_DSN,
TARGET_AUDIT_DSN, TARGET_KRATOS_ADMIN_URL, TARGET_VAULT_ADDR, TARGET_AUDIT_ADDR,
TARGET_TOTP_ENC_KEY, and optionally MIGRATE_PRINCIPAL, WORKLOAD_TOKEN_FILE and
MIGRATE_OWNER_PASSWORD_FILE (where --owner-email's password goes instead of
the terminal; the file must not exist).`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if o.bundle == "" || o.identity == "" {
				return usage("--bundle and --identity are required")
			}
			if !o.rehearsal && o.mapping == "" {
				cmd.SilenceUsage = true
				return codes.Wrap(codes.ModeRefused, errors.New("an import outside rehearsal mode needs the owner's approved mapping file (--mapping)"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			l := lg(cmd)
			cfg, err := config.LoadTarget(e.getenv)
			if err != nil {
				return usage("%v", err)
			}
			b, err := readBundle(o.bundle, o.identity)
			if err != nil {
				return err
			}
			plan, err := readPlan(o.mapping)
			if err != nil {
				return err
			}
			tc := target.Config{DSN: cfg.DSN, Rehearsal: o.rehearsal, Wipe: o.wipe, OwnerEmail: o.ownerEmail, Actor: cfg.Principal, Plan: plan}
			if cfg.TOTPKey != "" {
				if tc.TOTP, err = totpcipher.Parse(cfg.TOTPKey); err != nil {
					return codes.Wrap(codes.TargetKey, err)
				}
			}
			conns, err := dialTarget(ctxOf(cmd), cfg, l)
			if err != nil {
				return err
			}
			defer conns.Close()
			out, ierr := target.Import(ctxOf(cmd), tc, b, target.Deps{Sealer: conns.Vault, Recorder: conns.Audit, Kratos: conns.Kratos}, l)
			if out == nil {
				return ierr
			}
			if err := out.Report.Text(cmd.OutOrStdout()); err != nil {
				return err
			}
			if o.report != "" {
				if err := report.WriteFile(o.report, out.Report); err != nil {
					return err
				}
			}
			if ierr != nil {
				return ierr
			}
			if out.OwnerPassword != "" && e.getenv("MIGRATE_OWNER_PASSWORD_FILE") != "" {
				// A runner that shows it once itself (the appliance's Import page)
				// takes it from this file; it never reaches the output.
				path := e.getenv("MIGRATE_OWNER_PASSWORD_FILE")
				f, err := createExclusive(path)
				if err != nil {
					return err
				}
				if _, err := f.WriteString(out.OwnerPassword + "\n"); err != nil {
					_ = f.Close()
					return err
				}
				if err := f.Close(); err != nil {
					return err
				}
				pr := report.NewPrinter(cmd.ErrOrStderr())
				pr.F("\nfirst sign-in for %s: the one-time password is in the owner password file\n", o.ownerEmail)
				return pr.Err()
			}
			if out.OwnerPassword != "" {
				// Shown once, on the terminal; never in the report or the log.
				pr := report.NewPrinter(cmd.ErrOrStderr())
				pr.F("\nfirst sign-in for %s (shown once; change it and enrol a second factor at first sign-in): %s\n", o.ownerEmail, out.OwnerPassword)
				return pr.Err()
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.bundle, "bundle", "b", "", "the bundle file")
	f.StringVarP(&o.identity, "identity", "i", "", "the import identity file (from keygen)")
	f.BoolVarP(&o.rehearsal, "rehearsal", "R", false, "rehearsal mode: KEK rotation off; the mapping file is optional")
	f.BoolVarP(&o.wipe, "wipe-target", "w", false, "empty the target first (rehearsal, or a re-import over an earlier import)")
	f.StringVarP(&o.ownerEmail, "owner-email", "e", "", "give this account a new random password, shown once (rehearsal, or a sign-in reset bundle)")
	f.StringVarP(&o.mapping, "mapping", "m", "", "the owner's approved mapping file (required outside rehearsal)")
	f.StringVarP(&o.report, "report", "o", "", "also write the report as JSON to this file")
	return cmd
}
