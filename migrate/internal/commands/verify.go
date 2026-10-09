// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"errors"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/config"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/verify"
	"github.com/spf13/cobra"
)

type verifyOptions struct {
	bundle   string
	identity string
	report   string
	mapping  string
}

// VerifyCmd checks the target against the bundle.
func VerifyCmd(e env, lg logFn) *cobra.Command {
	o := &verifyOptions{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Check the target against the bundle it was imported from",
		Long: `verify checks per-table counts against the manifest, the audit chain from genesis
to head (through the audit service and by its own walk), sample reveals of the
designated test secrets' current values by keyed hash, every secret's older
versions by number, timestamp and sealed fields (never revealed), that every
target resolves to its connection and secrets, the parity table, that the
import applied the same --mapping file, that a sign-in reset held, and that
every active personal token still authenticates (by id). Any mismatch fails
the run (exit code 4).

Environment: as for import.`,
		Args: cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.bundle == "" || o.identity == "" {
				return usage("--bundle and --identity are required")
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
			conns, err := dialTarget(cfg)
			if err != nil {
				return err
			}
			defer conns.Close()
			rep, err := verify.Run(ctxOf(cmd), verify.Config{DSN: cfg.DSN, Plan: plan}, b, conns.Vault, conns.Audit, conns.Kratos, l)
			if err != nil {
				return err
			}
			if err := rep.Text(cmd.OutOrStdout()); err != nil {
				return err
			}
			if o.report != "" {
				if err := report.WriteFile(o.report, rep); err != nil {
					return err
				}
			}
			if !rep.OK {
				return codes.Wrap(codes.VerifyMismatch, errors.New("verify failed: the target does not match the bundle"))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.bundle, "bundle", "b", "", "the bundle file")
	f.StringVarP(&o.identity, "identity", "i", "", "the import identity file (from keygen)")
	f.StringVarP(&o.report, "report", "o", "", "also write the report as JSON to this file")
	f.StringVarP(&o.mapping, "mapping", "m", "", "the mapping file the import applied")
	return cmd
}
