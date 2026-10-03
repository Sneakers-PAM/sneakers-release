// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"os"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/config"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/envelope"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/source"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/totpcipher"
	"github.com/spf13/cobra"
)

type exportOptions struct {
	recipient string
	out       string
	samples   []string
	sampleMax int
}

// ExportCmd reads the source and writes the encrypted bundle.
func ExportCmd(e env, lg logFn) *cobra.Command {
	o := &exportOptions{}
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Read the source system and write one encrypted bundle",
		Long: `export reads the four source databases in read-only snapshots and the source
Kratos, opens every sealed value with the source key ring in memory, checks the
audit chain, and writes one bundle encrypted to --recipient. Nothing is written
to the source and no plaintext is written to disk.

Environment: SOURCE_IDENTITY_DSN, SOURCE_VAULT_DSN, SOURCE_WORKFLOW_DSN,
SOURCE_AUDIT_DSN, SOURCE_KRATOS_ADMIN_URL, SOURCE_VAULT_ROOT_KEK, and when the
source has them SOURCE_DEV_KEK_SEED and SOURCE_TOTP_ENC_KEY.`,
		Args: cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.recipient == "" || o.out == "" {
				return usage("--recipient and --out are required")
			}
			if _, err := bundle.ParseRecipient(o.recipient); err != nil {
				return usage("%v", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			l := lg(cmd)
			cfg, err := config.LoadSource(e.getenv)
			if err != nil {
				return usage("%v", err)
			}
			root, err := envelope.ParseRootKey(cfg.RootKey)
			if err != nil {
				return codes.Wrap(codes.SourceValue, err)
			}
			sc := source.Config{DSN: cfg.DSN, RootKey: root, DevSeed: cfg.DevSeed, Samples: o.samples, SampleMax: o.sampleMax}
			if cfg.TOTPKey != "" {
				if sc.TOTP, err = totpcipher.Parse(cfg.TOTPKey); err != nil {
					return codes.Wrap(codes.SourceValue, err)
				}
			}
			rcpt, _ := bundle.ParseRecipient(o.recipient)
			b, err := source.Export(ctxOf(cmd), sc, kratos.New(cfg.KratosAdminURL), l)
			if err != nil {
				return err
			}
			f, err := createExclusive(o.out)
			if err != nil {
				return err
			}
			if err := bundle.Write(f, b, rcpt); err != nil {
				_ = f.Close()
				_ = os.Remove(o.out)
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			pr := report.NewPrinter(cmd.OutOrStdout())
			pr.F("bundle %s written to %s (source profile %s)\n", b.Manifest.BundleID, o.out, b.Manifest.Profile)
			pr.F("  %-36s %8s\n", "table", "rows")
			for _, t := range b.Manifest.Tables {
				pr.F("  %-36s %8d\n", t.Name, t.Rows)
			}
			pr.F("audit chain head: seq %d\nsample values: %d\n", b.Manifest.AuditHead.Seq, len(b.Manifest.Samples))
			for _, n := range b.Manifest.NotCarried {
				pr.F("not carried: %s (%d rows): %s\n", n.Name, n.Rows, n.Reason)
			}
			return pr.Err()
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.recipient, "recipient", "r", "", "the target's import recipient (age1..., from keygen)")
	f.StringVarP(&o.out, "out", "o", "", "bundle file to write (created 0600; must not exist)")
	f.StringSliceVarP(&o.samples, "sample-secret", "s", nil, "designated test secret for the sample reveals (repeatable; default: picked evenly)")
	f.IntVarP(&o.sampleMax, "samples", "n", 10, "how many test secrets to pick when none are designated")
	return cmd
}
