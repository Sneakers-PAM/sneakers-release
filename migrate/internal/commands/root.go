// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package commands holds the sneakers-migrate command line.
package commands

import (
	"io"
	"os"

	log "github.com/Bugs5382/go-log"
	"github.com/spf13/cobra"
)

// UsageError marks a bad flag or argument, so run can map it to its exit code.
type UsageError struct{ Err error }

func (e *UsageError) Error() string { return e.Err.Error() }
func (e *UsageError) Unwrap() error { return e.Err }

// env is the process environment, a seam for tests.
type env struct {
	getenv func(string) string
	stderr io.Writer
}

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	return rootWith(env{getenv: os.Getenv})
}

func rootWith(e env) *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "sneakers-migrate",
		Short: "Move a Sneakers install to Sneakers-PAM: export, import and verify",
		Long: `sneakers-migrate moves an install of the original system to Sneakers-PAM.

  keygen   make the import key pair on the target side
  export   read the source and write one encrypted bundle
  review   list a bundle's secrets by folder, name and type
  mapping  convert a proposal sheet into a mapping file, or check one
  import   load the bundle into a fresh target install
  verify   check the target against the bundle
  wait     block until a DNS name and TCP targets answer (for an init container)

Connection settings and keys come from the environment; see docs/migrate.md.`,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "log at trace level")
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &UsageError{Err: err} })
	lg := func(c *cobra.Command) log.Logger {
		level := log.LevelInfo
		if verbose {
			level = log.LevelTrace
		}
		out := e.stderr
		if out == nil {
			out = c.ErrOrStderr()
		}
		return log.NewLoggerWithOptions("sneakers-migrate", log.WithOutput(out), log.WithDefaultFormat(log.FormatConsole), log.WithDefaultLevel(level))
	}
	cmd.AddCommand(KeygenCmd(), ExportCmd(e, lg), ReviewCmd(), MappingCmd(), ImportCmd(e, lg), VerifyCmd(e, lg), WaitCmd(lg), VersionCmd())
	return cmd
}
