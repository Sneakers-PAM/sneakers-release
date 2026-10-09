// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"os"
	"sort"

	log "github.com/Bugs5382/go-log"

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
	recipient   string
	out         string
	samples     []string
	sampleMax   int
	currentOnly bool
	resetSignIn bool
	inventory   bool
	sanitise    bool
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
to the source and no plaintext is written to disk. It counts folders, secrets,
types, users, targets and connections in the source and prints them next to
the bundle's (the parity report); a difference stops it.

--current-only carries each secret's current value without its history.
--reset-sign-in carries no password hash, TOTP seed or passkey: every user
sets a new password and enrols a second factor on the target (and
SOURCE_TOTP_ENC_KEY isn't needed).

--sanitise writes a lab dry-run bundle: the same folders, names, types,
targets, users and rules, with every secret value, token hash and target
address replaced by a fake; import takes it in rehearsal mode only.

--inventory reads counts and names only (per table, folder, type and role,
the personal tokens by id, the schedules), needs no key, writes no bundle and
prints the inventory; --out, when given, gets it as JSON.

Environment: SOURCE_IDENTITY_DSN, SOURCE_VAULT_DSN, SOURCE_WORKFLOW_DSN,
SOURCE_AUDIT_DSN, SOURCE_KRATOS_ADMIN_URL, SOURCE_VAULT_ROOT_KEK, and when the
source has them SOURCE_DEV_KEK_SEED and SOURCE_TOTP_ENC_KEY.`,
		Args: cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.inventory {
				return nil
			}
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
			if o.inventory {
				return runInventory(cmd, e, l, o.out)
			}
			cfg, err := config.LoadSource(e.getenv)
			if err != nil {
				return usage("%v", err)
			}
			root, err := envelope.ParseRootKey(cfg.RootKey)
			if err != nil {
				return codes.Wrap(codes.SourceValue, err)
			}
			sc := source.Config{DSN: cfg.DSN, RootKey: root, DevSeed: cfg.DevSeed, Samples: o.samples, SampleMax: o.sampleMax, CurrentOnly: o.currentOnly, ResetSignIn: o.resetSignIn, Sanitise: o.sanitise}
			if cfg.TOTPKey != "" && !o.resetSignIn && !o.sanitise {
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
			pr.F("parity (source / bundle):\n")
			for _, p := range b.Manifest.Parity {
				pr.F("  %-12s %6d %6d  ok\n", p.Name, p.Source, p.Bundle)
			}
			return pr.Err()
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.recipient, "recipient", "r", "", "the target's import recipient (age1..., from keygen)")
	f.StringVarP(&o.out, "out", "o", "", "bundle file to write (created 0600; must not exist)")
	f.StringSliceVarP(&o.samples, "sample-secret", "s", nil, "designated test secret for the sample reveals (repeatable; default: picked evenly)")
	f.IntVarP(&o.sampleMax, "samples", "n", 10, "how many test secrets to pick when none are designated")
	f.BoolVarP(&o.currentOnly, "current-only", "c", false, "carry each secret's current value only, without its history")
	f.BoolVarP(&o.resetSignIn, "reset-sign-in", "x", false, "carry no password hash, TOTP seed or passkey; every user signs up again")
	f.BoolVarP(&o.inventory, "inventory", "I", false, "counts and names only: no key, no bundle")
	f.BoolVarP(&o.sanitise, "sanitise", "S", false, "a lab dry-run bundle: the real shape, every value a fake (implies --reset-sign-in)")
	return cmd
}

func runInventory(cmd *cobra.Command, e env, l log.Logger, out string) error {
	cfg, err := config.LoadInventory(e.getenv)
	if err != nil {
		return usage("%v", err)
	}
	var kr source.Lister
	if cfg.KratosAdminURL != "" {
		kr = kratos.New(cfg.KratosAdminURL)
	}
	inv, err := source.Inventory(ctxOf(cmd), cfg.DSN, kr, l)
	if err != nil {
		return err
	}
	pr := report.NewPrinter(cmd.OutOrStdout())
	pr.F("inventory of the %s source at %s (counts and names only)\n", inv.Profile, inv.At)
	for _, k := range sortedKeys(inv.Tables) {
		pr.F("  %-36s %8d\n", k, inv.Tables[k])
	}
	pr.F("kratos identities: %d\nusers by role:\n", inv.KratosIdentities)
	for _, k := range sortedKeys(inv.UsersByRole) {
		pr.F("  %-36s %8d\n", k, inv.UsersByRole[k])
	}
	pr.F("secrets by type:\n")
	for _, k := range sortedKeys(inv.ByType) {
		pr.F("  %-36s %8d\n", k, inv.ByType[k])
	}
	pr.F("secrets by folder:\n")
	for _, k := range sortedKeys(inv.ByFolder) {
		pr.F("  %-36s %8d\n", k, inv.ByFolder[k])
	}
	active := 0
	for _, t := range inv.PersonalTokens {
		if t.Active {
			active++
		}
	}
	pr.F("personal tokens: %d (%d active)\nrotation schedules: %d, heartbeat schedules: %d\n", len(inv.PersonalTokens), active, inv.RotationSchedules, inv.HeartbeatSchedule)
	if err := pr.Err(); err != nil {
		return err
	}
	if out != "" {
		return report.WriteFile(out, inv)
	}
	return nil
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
