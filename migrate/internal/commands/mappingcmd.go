// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"time"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
	"github.com/spf13/cobra"
)

type mappingOptions struct {
	bundle, identity string
	tsv, types       string
	parent, personal string
	out, check       string
}

// MappingCmd converts a proposal sheet into a mapping file, or checks one,
// against a bundle.
func MappingCmd() *cobra.Command {
	o := &mappingOptions{}
	cmd := &cobra.Command{
		Use:   "mapping",
		Short: "Convert a proposal sheet into a mapping file, or check a mapping file, against a bundle",
		Long: `mapping resolves a mapping against the bundle without writing anything.

With --tsv it converts a proposal sheet (one row per secret: current_folder,
current_name, current_type, new_folder, new_name, new_type, action carry or
drop, and optionally id) into a mapping file at --out, with each row pinned to
its secret's id. --types adds the field mapping of each type change (a JSON
list of {from, to, fields, drop_fields}). With --check it reads a mapping
file. Either way it then applies the mapping to the bundle in memory and
prints what would change; an error names the rule that doesn't fit.`,
		Args: cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.bundle == "" || o.identity == "" {
				return usage("--bundle and --identity are required")
			}
			if (o.tsv == "") == (o.check == "") {
				return usage("give either --tsv (with --out) or --check")
			}
			if o.tsv != "" && o.out == "" {
				return usage("--tsv needs --out")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			b, err := readBundle(o.bundle, o.identity)
			if err != nil {
				return err
			}
			path := o.check
			if o.tsv != "" {
				if err := convertSheet(b, o); err != nil {
					return err
				}
				path = o.out
			}
			plan, err := readPlan(path)
			if err != nil {
				return err
			}
			m, err := mapping.Map(b, mapping.Context{Now: time.Now(), Actor: "system:sneakers-migrate", Plan: plan})
			if err != nil {
				return codes.Wrap(codes.MappingInvalid, err)
			}
			st := m.Remap
			pr := report.NewPrinter(cmd.OutOrStdout())
			pr.F("mapping %s fits bundle %s\n", plan.SHA256, b.Manifest.BundleID)
			pr.F("  folders: %d moved, %d created, %d dropped\n  secrets: %d moved, %d renamed, %d retyped, %d dropped, %d not listed (kept as they are)\n",
				st.FoldersMoved, st.FoldersCreated, st.FoldersDropped, st.SecretsMoved, st.SecretsRenamed, st.SecretsRetyped, st.SecretsDropped, st.SecretsKept)
			for _, w := range st.Warnings {
				pr.F("warning: %s\n", w)
			}
			return pr.Err()
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.bundle, "bundle", "b", "", "the bundle file")
	f.StringVarP(&o.identity, "identity", "i", "", "the import identity file (from keygen)")
	f.StringVarP(&o.tsv, "tsv", "t", "", "a proposal sheet to convert")
	f.StringVarP(&o.types, "types", "y", "", "a JSON list of type rules for the sheet's type changes")
	f.StringVarP(&o.parent, "new-folder-parent", "p", "", "where the sheet's new folders go (a path; default the root)")
	f.StringVarP(&o.personal, "personal", "u", "", "the email whose personal folder the sheet's \"Personal\" rows are in")
	f.StringVarP(&o.out, "out", "o", "", "the mapping file to write (must not exist)")
	f.StringVarP(&o.check, "check", "c", "", "a mapping file to check")
	return cmd
}

func convertSheet(b *bundle.Bundle, o *mappingOptions) error {
	in, err := os.ReadFile(o.tsv) // #nosec G304 -- the operator names the sheet
	if err != nil {
		return err
	}
	var types []mapping.TypeRule
	if o.types != "" {
		raw, err := os.ReadFile(o.types) // #nosec G304 -- the operator names the type rules
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &types); err != nil {
			return codes.Wrap(codes.MappingInvalid, err)
		}
	}
	var parent mapping.Path
	if o.parent != "" {
		if err := json.Unmarshal([]byte(`"`+o.parent+`"`), &parent); err != nil {
			return usage("--new-folder-parent: %v", err)
		}
	}
	m, err := mapping.Map(b, mapping.Context{Now: time.Now(), Actor: "system:sneakers-migrate"})
	if err != nil {
		return err
	}
	p, _, err := mapping.PlanFromTSV(bytes.NewReader(in), m, parent, o.personal, types)
	if err != nil {
		return codes.Wrap(codes.MappingInvalid, err)
	}
	f, err := createExclusive(o.out)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
