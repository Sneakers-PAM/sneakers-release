// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package synth_test

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/source"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/synth"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/testenv"
)

func TestShapedSourceExports(t *testing.T) {
	sh := &synth.Shape{
		Folders:    []synth.ShapeFolder{{Path: []string{"Infrastructure"}}, {Path: []string{"Infrastructure", "Vendor A"}}, {Path: []string{"Personal"}, PersonalOwner: 1}},
		Types:      []synth.ShapeType{{Name: "Web Password", Template: "web"}, {Name: "Windows Domain Account", Template: "legacy-domain"}, {Name: "Key Store", Template: "custom"}},
		Secrets:    []synth.ShapeSecret{{Folder: 1, Type: 0, Name: "portal admin"}, {Folder: 0, Type: 1, Name: "svc", Target: 2}, {Folder: 2, Type: 2, Name: "mine"}},
		SSHTargets: 1, LDAPTargets: 1,
	}
	src := testenv.NewSource(t, synth.Options{Users: 4, Secrets: 3, AuditRecords: 10, Shape: sh})
	b, err := source.Export(context.Background(), src.Config, kratos.New(src.Kratos.URL), log.Nop())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	for stream, want := range map[string]int{"vault.folders": 3, "vault.secret_types": 3, "vault.secrets": 3, "vault.targets": 2, "vault.connections": 3} {
		if tb, _ := b.Manifest.Table(stream); tb.Rows != want {
			t.Fatalf("%s = %d, want %d", stream, tb.Rows, want)
		}
	}
}
