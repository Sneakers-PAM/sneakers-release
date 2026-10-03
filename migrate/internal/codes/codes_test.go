// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRegistryAndChain(t *testing.T) {
	if _, err := Registry(); err != nil {
		t.Fatalf("Registry: %v", err)
	}
	base := errors.New("boom")
	err := fmt.Errorf("outer: %w", Wrap(TargetNotEmpty, base))
	if c, ok := Of(err); !ok || c != TargetNotEmpty {
		t.Fatalf("Of = %d, %v", c, ok)
	}
	if !errors.Is(err, base) {
		t.Fatal("the cause must stay on the chain")
	}
}

// TestDocsListEveryCode keeps the table in docs/migrate.md in step with the
// registry.
func TestDocsListEveryCode(t *testing.T) {
	r, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../../docs/migrate.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), r.Markdown()) {
		t.Fatalf("docs/migrate.md must carry the error-code table exactly as the registry renders it:\n%s", r.Markdown())
	}
}
