// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package rpc holds the gRPC clients import and verify use: the target vault
// (seal for import, reveal, targets) and the target audit service (record an
// event, verify the chain). The stubs come from the callee protos pinned in
// proto-refs.env; no service module is imported.
package rpc

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	auditv1 "github.com/Sneakers-PAM/sneakers-release/gen/go/thirdparty/audit/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-release/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// SealBatch is the most items one SealForImport call takes.
const SealBatch = 200

const callTimeout = 60 * time.Second

// Dial connects to a service's gRPC address inside the cluster. A non-empty
// tokenFile is the projected ServiceAccount token (audience sneakers) sent as
// the caller's workload identity on every call, read again each time so a
// rotated token is picked up.
func Dial(addr, tokenFile string) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if tokenFile != "" {
		if _, err := os.ReadFile(tokenFile); err != nil { // #nosec G304 -- the operator-set WORKLOAD_TOKEN_FILE
			return nil, fmt.Errorf("workload token: %w", err)
		}
		opts = append(opts, grpc.WithPerRPCCredentials(tokenCreds(tokenFile)))
	}
	cc, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return cc, nil
}

type tokenCreds string

func (f tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	raw, err := os.ReadFile(string(f))
	if err != nil {
		return nil, fmt.Errorf("workload token: %w", err)
	}
	return map[string]string{"authorization": "Bearer " + strings.TrimSpace(string(raw))}, nil
}

func (tokenCreds) RequireTransportSecurity() bool { return false }

// Vault calls the target vault. sneakers-migrate is a Self caller there: it
// sends no actor, and the vault acts for it as its own system actor.
type Vault struct {
	c vaultv1.VaultServiceClient
}

// NewVault wraps a connection.
func NewVault(cc grpc.ClientConnInterface) *Vault {
	return &Vault{c: vaultv1.NewVaultServiceClient(cc)}
}

// Seal seals each field set under the target vault's active key, in batches,
// and returns the stored envelopes in order.
func (v *Vault) Seal(ctx context.Context, items []map[string]string) ([][]byte, error) {
	out := make([][]byte, 0, len(items))
	for start := 0; start < len(items); start += SealBatch {
		end := min(start+SealBatch, len(items))
		req := &vaultv1.SealForImportRequest{}
		for _, f := range items[start:end] {
			req.Items = append(req.Items, &vaultv1.SealForImportItem{Fields: f})
		}
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		resp, err := v.c.SealForImport(cctx, req)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("vault SealForImport (items %d-%d): %w", start, end-1, err)
		}
		if len(resp.GetRecords()) != end-start {
			return nil, fmt.Errorf("vault SealForImport returned %d records for %d items", len(resp.GetRecords()), end-start)
		}
		out = append(out, resp.GetRecords()...)
	}
	return out, nil
}

// Reveal returns one field of a secret's current value. Older versions are
// never revealed: verify checks them without reading their values.
func (v *Vault) Reveal(ctx context.Context, secretID string, field string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := v.c.RevealSecretField(cctx, &vaultv1.RevealSecretFieldRequest{Id: secretID, FieldKey: field})
	if err != nil {
		return "", err
	}
	return resp.GetValue(), nil
}

// Target is a target as verify checks it.
type Target struct {
	ID, Name, Hostname, ConnectionID string
	Pinned                           bool
}

// Connection is a connection as verify checks it.
type Connection struct {
	ID, Protocol, PrivilegedSecretID string
}

// Targets lists every target.
func (v *Vault) Targets(ctx context.Context) ([]Target, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := v.c.ListTargets(cctx, &vaultv1.ListTargetsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]Target, 0, len(resp.GetTargets()))
	for _, t := range resp.GetTargets() {
		out = append(out, Target{ID: t.GetId(), Name: t.GetName(), Hostname: t.GetHostname(), ConnectionID: t.GetConnectionId(), Pinned: len(t.GetSshHostKeys()) > 0})
	}
	return out, nil
}

// Connections lists every connection.
func (v *Vault) Connections(ctx context.Context) ([]Connection, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := v.c.ListConnections(cctx, &vaultv1.ListConnectionsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(resp.GetConnections()))
	for _, c := range resp.GetConnections() {
		out = append(out, Connection{ID: c.GetId(), Protocol: c.GetProtocol(), PrivilegedSecretID: c.GetPrivilegedSecretId()})
	}
	return out, nil
}

// SecretExists reports whether the vault resolves a secret id.
func (v *Vault) SecretExists(ctx context.Context, id string) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := v.c.GetSecret(cctx, &vaultv1.GetSecretRequest{Id: id})
	if err != nil {
		return false, err
	}
	return resp.GetSecret().GetId() == id, nil
}

// Audit calls the target audit service.
type Audit struct{ c auditv1.AuditServiceClient }

// NewAudit wraps a connection.
func NewAudit(cc grpc.ClientConnInterface) *Audit {
	return &Audit{c: auditv1.NewAuditServiceClient(cc)}
}

// Event is one record to append.
type Event struct {
	Actor, Action, Subject string
	Attributes             map[string]string
}

// Record appends an event to the chain (tier audit); the audit service
// computes its hash.
func (a *Audit) Record(ctx context.Context, e Event) error {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, err := a.c.RecordEvent(cctx, &auditv1.RecordEventRequest{
		Tier: auditv1.Tier_TIER_AUDIT, Action: e.Action, ActorUserId: e.Actor, Subject: e.Subject, Attributes: e.Attributes,
	})
	return err
}

// VerifyChain asks the audit service to verify its chain.
func (a *Audit) VerifyChain(ctx context.Context) (bool, uint64, uint64, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*callTimeout)
	defer cancel()
	resp, err := a.c.VerifyChain(cctx, &auditv1.VerifyChainRequest{})
	if err != nil {
		return false, 0, 0, err
	}
	return resp.GetValid(), resp.GetBrokenAtSeq(), resp.GetLength(), nil
}
