// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"fmt"
	"runtime/debug"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
	"github.com/spf13/cobra"
)

// Version is set at build time (-ldflags "-X .../commands.Version=v0.1.0").
var Version = ""

// VersionCmd prints the tool version, the bundle format and the source
// profile it reads.
func VersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version, the bundle format and the source profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := Version
			if v == "" {
				v = "dev"
				if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
					v = bi.Main.Version
				}
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "sneakers-migrate %s\nbundle format %s %s\nsource profile %s\n", v, bundle.Format, bundle.FormatVersion, schema.SourceProfile.Name)
			return err
		},
	}
}
