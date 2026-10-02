// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-migrate moves an install of the original system to
// Sneakers-PAM: keygen, export, import and verify.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/commands"
)

// Exit codes are part of the command-line contract (docs/migrate.md).
const (
	// exitOK: the command did what it was asked.
	exitOK = 0
	// exitError: anything else went wrong (a connection, a file, a service).
	exitError = 1
	// exitUsage: a bad flag, argument or missing setting.
	exitUsage = 2
	// exitRefused: the source or target refused (version, non-empty target,
	// a flag outside rehearsal mode, a missing key).
	exitRefused = 3
	// exitVerify: verify found the target doesn't match the bundle.
	exitVerify = 4
	// exitBundle: the bundle won't open with this identity, or is damaged or
	// from another major version.
	exitBundle = 5
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd := commands.RootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SilenceErrors = true
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	// Nothing is left to report a failed write of the error itself to.
	_, _ = fmt.Fprintln(stderr, "sneakers-migrate:", err)
	return exitCode(err)
}

func exitCode(err error) int {
	var ue *commands.UsageError
	if errors.As(err, &ue) {
		return exitUsage
	}
	c, ok := codes.Of(err)
	switch {
	case !ok:
		return exitError
	case c >= 1000 && c < 3000:
		return exitRefused
	case c >= 3000 && c < 4000:
		return exitVerify
	case c >= 4000 && c < 5000:
		return exitBundle
	}
	return exitError
}
