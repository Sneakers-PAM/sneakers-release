// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"context"
	"errors"
	"fmt"
	"os"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/codes"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/config"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/rpc"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

type logFn func(*cobra.Command) log.Logger

func usage(format string, a ...any) error { return &UsageError{Err: fmt.Errorf(format, a...)} }

// readBundle opens and checks a bundle with the identity file.
func readBundle(bundlePath, identityPath string) (*bundle.Bundle, error) {
	idf, err := os.Open(identityPath) // #nosec G304 -- the operator names the identity file
	if err != nil {
		return nil, codes.Wrap(codes.BundleKey, err)
	}
	defer func() { _ = idf.Close() }()
	ids, err := bundle.ParseIdentities(idf)
	if err != nil {
		return nil, codes.Wrap(codes.BundleKey, err)
	}
	f, err := os.Open(bundlePath) // #nosec G304 -- the operator names the bundle
	if err != nil {
		return nil, codes.Wrap(codes.BundleDamaged, err)
	}
	defer func() { _ = f.Close() }()
	b, err := bundle.Read(f, ids...)
	switch {
	case errors.Is(err, bundle.ErrDecrypt):
		return nil, codes.Wrap(codes.BundleKey, err)
	case errors.Is(err, bundle.ErrVersion):
		return nil, codes.Wrap(codes.BundleVersion, err)
	case err != nil:
		return nil, codes.Wrap(codes.BundleDamaged, err)
	}
	return b, nil
}

// targetConns holds the target's vault and audit services.
type targetConns struct {
	vault, audit *grpc.ClientConn
	Vault        *rpc.Vault
	Audit        *rpc.Audit
	Kratos       *kratos.Admin
}

func dialTarget(t config.Target) (*targetConns, error) {
	vc, err := rpc.Dial(t.VaultAddr, t.TokenFile)
	if err != nil {
		return nil, err
	}
	ac, err := rpc.Dial(t.AuditAddr, t.TokenFile)
	if err != nil {
		_ = vc.Close()
		return nil, err
	}
	return &targetConns{
		vault: vc, audit: ac,
		Vault:  rpc.NewVault(vc),
		Audit:  rpc.NewAudit(ac),
		Kratos: kratos.New(t.KratosAdminURL),
	}, nil
}

func (c *targetConns) Close() {
	_ = c.vault.Close()
	_ = c.audit.Close()
}

// createExclusive creates a new file that must not exist yet.
func createExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the operator names the output
}

func ctxOf(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
