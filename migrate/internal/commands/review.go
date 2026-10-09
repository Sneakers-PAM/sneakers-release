// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"encoding/json"
	"time"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
	"github.com/spf13/cobra"
)

type reviewOptions struct {
	bundle   string
	identity string
	report   string
	template string
}

// ReviewCmd lists a bundle's secrets by folder, name and type.
func ReviewCmd() *cobra.Command {
	o := &reviewOptions{}
	cmd := &cobra.Command{
		Use:   "review",
		Short: "List a bundle's secrets by folder, name and type, and write a mapping template",
		Long: `review opens the bundle in memory and lists every secret by folder, name and
type (personal folders with their owner), with counts per type and per folder
and the unused types. It never prints a value. --template writes a mapping
file that keeps everything as it is, one entry per secret, for the owner's
decisions to be written into; docs/migrate.md#the-mapping-file has the format.`,
		Args: cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.bundle == "" || o.identity == "" {
				return usage("--bundle and --identity are required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			b, err := readBundle(o.bundle, o.identity)
			if err != nil {
				return err
			}
			m, err := mapping.Map(b, mapping.Context{Now: time.Now(), Actor: "system:sneakers-migrate"})
			if err != nil {
				return err
			}
			rv, err := mapping.Review(m)
			if err != nil {
				return err
			}
			if err := rv.Text(cmd.OutOrStdout()); err != nil {
				return err
			}
			if o.report != "" {
				if err := report.WriteFile(o.report, rv); err != nil {
					return err
				}
			}
			if o.template != "" {
				f, err := createExclusive(o.template)
				if err != nil {
					return err
				}
				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rv.Template(b.Manifest.BundleID)); err != nil {
					_ = f.Close()
					return err
				}
				return f.Close()
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.bundle, "bundle", "b", "", "the bundle file")
	f.StringVarP(&o.identity, "identity", "i", "", "the import identity file (from keygen)")
	f.StringVarP(&o.report, "report", "o", "", "also write the review as JSON to this file")
	f.StringVarP(&o.template, "template", "t", "", "write a keep-everything mapping file here (must not exist)")
	return cmd
}
