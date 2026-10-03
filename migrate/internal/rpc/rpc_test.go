// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-release/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

func TestTokenIsReadOnEveryCall(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := tokenCreds(f)
	md, err := c.GetRequestMetadata(context.Background())
	if err != nil || md["authorization"] != "Bearer first" {
		t.Fatalf("metadata = %v, %v", md, err)
	}
	if err := os.WriteFile(f, []byte("rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if md, _ := c.GetRequestMetadata(context.Background()); md["authorization"] != "Bearer rotated" {
		t.Fatalf("a rotated token was not picked up: %v", md)
	}
	if _, err := Dial("vault.example.org:9091", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing token file must fail the dial")
	}
}

// recordingVault records each request the client sends.
type recordingVault struct {
	vaultv1.VaultServiceClient
	actors []string
}

func (r *recordingVault) note(method string, a *vaultv1.ActorContext) {
	if a != nil {
		r.actors = append(r.actors, method)
	}
}

func (r *recordingVault) SealForImport(_ context.Context, req *vaultv1.SealForImportRequest, _ ...grpc.CallOption) (*vaultv1.SealForImportResponse, error) {
	r.note("SealForImport", req.GetActor())
	out := &vaultv1.SealForImportResponse{}
	for range req.GetItems() {
		out.Records = append(out.Records, []byte("{}"))
	}
	return out, nil
}

func (r *recordingVault) RevealSecretField(_ context.Context, req *vaultv1.RevealSecretFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldResponse, error) {
	r.note("RevealSecretField", req.GetActor())
	return &vaultv1.RevealSecretFieldResponse{}, nil
}

func (r *recordingVault) ListTargets(_ context.Context, req *vaultv1.ListTargetsRequest, _ ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	r.note("ListTargets", req.GetActor())
	return &vaultv1.ListTargetsResponse{}, nil
}

func (r *recordingVault) ListConnections(context.Context, *vaultv1.ListConnectionsRequest, ...grpc.CallOption) (*vaultv1.ListConnectionsResponse, error) {
	return &vaultv1.ListConnectionsResponse{}, nil
}

func (r *recordingVault) GetSecret(_ context.Context, req *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	r.note("GetSecret", req.GetActor())
	return &vaultv1.GetSecretResponse{}, nil
}

// The vault admits sneakers-migrate as a Self caller and refuses any actor
// it sends, so no vault call may carry one.
func TestVaultCallsCarryNoActor(t *testing.T) {
	ctx := context.Background()
	rec := &recordingVault{}
	v := &Vault{c: rec}
	if _, err := v.Seal(ctx, []map[string]string{{"password": "x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Reveal(ctx, "sec-1", "password"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Targets(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Connections(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := v.SecretExists(ctx, "sec-1"); err != nil {
		t.Fatal(err)
	}
	if len(rec.actors) > 0 {
		t.Fatalf("these calls sent an actor: %v", rec.actors)
	}
}
