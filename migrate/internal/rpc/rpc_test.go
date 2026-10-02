// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
