// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"fmt"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

type keygenOptions struct {
	out string
}

// KeygenCmd makes the import key pair: the private identity goes to a new
// 0600 file the import reads, and the public recipient is printed for export.
func KeygenCmd() *cobra.Command {
	o := &keygenOptions{}
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Make the import key pair (an age X25519 identity) on the target side",
		Long: `keygen writes a new age X25519 identity to --out (it must not exist) and prints
its public recipient. Give the recipient to export; keep the identity on the
target side for import and verify, and destroy it after the run.`,
		Args: cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.out == "" {
				return usage("--out is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			id, err := age.GenerateX25519Identity()
			if err != nil {
				return err
			}
			f, err := createExclusive(o.out)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(f, "# created: %s\n# recipient: %s\n%s\n", time.Now().UTC().Format(time.RFC3339), id.Recipient(), id); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), id.Recipient().String())
			return err
		},
	}
	cmd.Flags().StringVarP(&o.out, "out", "o", "", "file to write the identity to (created 0600; must not exist)")
	return cmd
}
