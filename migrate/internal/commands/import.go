// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"fmt"

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

--rehearsal imports with KEK rotation off and is the only mode that allows
--wipe-target and --owner-email. Restart the vault after an import.

Environment: TARGET_IDENTITY_DSN, TARGET_VAULT_DSN, TARGET_WORKFLOW_DSN,
TARGET_AUDIT_DSN, TARGET_KRATOS_ADMIN_URL, TARGET_VAULT_ADDR, TARGET_AUDIT_ADDR,
TARGET_TOTP_ENC_KEY, and optionally MIGRATE_PRINCIPAL and WORKLOAD_TOKEN_FILE.`,
		Args: cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.bundle == "" || o.identity == "" {
				return usage("--bundle and --identity are required")
			}
			if (o.wipe || o.ownerEmail != "") && !o.rehearsal {
				return codes.Wrap(codes.ModeRefused, fmt.Errorf("--wipe-target and --owner-email are only allowed with --rehearsal"))
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
			tc := target.Config{DSN: cfg.DSN, Rehearsal: o.rehearsal, Wipe: o.wipe, OwnerEmail: o.ownerEmail, Actor: cfg.Principal}
			if cfg.TOTPKey != "" {
				if tc.TOTP, err = totpcipher.Parse(cfg.TOTPKey); err != nil {
					return codes.Wrap(codes.TargetKey, err)
				}
			}
			conns, err := dialTarget(cfg)
			if err != nil {
				return err
			}
			defer conns.Close()
			out, err := target.Import(ctxOf(cmd), tc, b, target.Deps{Sealer: conns.Vault, Recorder: conns.Audit, Kratos: conns.Kratos}, l)
			if err != nil {
				return err
			}
			if err := out.Report.Text(cmd.OutOrStdout()); err != nil {
				return err
			}
			if o.report != "" {
				if err := report.WriteFile(o.report, out.Report); err != nil {
					return err
				}
			}
			if out.OwnerPassword != "" {
				// Shown once, on the terminal; never in the report or the log.
				pr := report.NewPrinter(cmd.ErrOrStderr())
				pr.F("\nrehearsal sign-in for %s (shown once): %s\n", o.ownerEmail, out.OwnerPassword)
				return pr.Err()
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.bundle, "bundle", "b", "", "the bundle file")
	f.StringVarP(&o.identity, "identity", "i", "", "the import identity file (from keygen)")
	f.BoolVarP(&o.rehearsal, "rehearsal", "R", false, "rehearsal mode: KEK rotation off; allows --wipe-target and --owner-email")
	f.BoolVarP(&o.wipe, "wipe-target", "w", false, "empty the target first (rehearsal only)")
	f.StringVarP(&o.ownerEmail, "owner-email", "e", "", "give this account a new random password, shown once (rehearsal only)")
	f.StringVarP(&o.report, "report", "o", "", "also write the report as JSON to this file")
	return cmd
}
