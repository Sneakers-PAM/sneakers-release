// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package mapping

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const fixtureTSV = "current_folder\tcurrent_name\tcurrent_type\tnew_folder\tnew_name\tnew_type\taction\n" +
	"ESXI\tesx01 root\tWeb Password\tVirtualisation\tesx01 - root\tWeb Password\tcarry\n" +
	"ESXI\tesx02 root\tPassword\tESXI\tesx02 root\tPassword\tcarry\n" +
	"Certs/PKI\tsvc account\tWindows Domain Account\tCerts-PKI\tsvc account\tActive Directory Account\tcarry\n" +
	"Retired stuff\told thing\tPassword\t\t\t\tdrop\n" +
	"Personal\tmy key\tPassword\tPersonal\tmy key\tPassword\tcarry\n"

func TestPlanFromTSV(t *testing.T) {
	r, err := Map(remapFixture(t), Context{Now: time.Now(), Actor: "system:sneakers-migrate"})
	if err != nil {
		t.Fatal(err)
	}
	types := []TypeRule{{From: "Windows Domain Account", To: "Active Directory Account", Fields: map[string]string{"user": "username", "pass": "password"}}}
	p, notes, err := PlanFromTSV(strings.NewReader(fixtureTSV), r, Path{"Infrastructure"}, "owner@example.org", types)
	if err != nil {
		t.Fatalf("PlanFromTSV: %v", err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePlan(raw)
	if err != nil {
		t.Fatalf("the converted plan doesn't parse: %v", err)
	}
	if len(parsed.Folders) != 1 || parsed.Folders[0].To.String() != "Infrastructure / Certs-PKI" {
		t.Fatalf("a folder whose secrets all go to one new name is renamed, keeping its rules: %+v", parsed.Folders)
	}
	if parsed.Unlisted != UnlistedKeep {
		t.Fatalf("unlisted = %q: other users' personal folders aren't in the file and stay as they are", parsed.Unlisted)
	}
	m, err := Map(remapFixture(t), Context{Now: time.Now(), Actor: "system:sneakers-migrate", Plan: parsed})
	if err != nil {
		t.Fatalf("the converted plan doesn't apply: %v", err)
	}
	st := m.Remap
	if st.SecretsDropped != 1 || st.SecretsMoved != 1 || st.SecretsRenamed != 1 || st.SecretsRetyped != 1 || st.FoldersMoved != 1 || st.FoldersCreated != 1 || st.SecretsKept != 1 {
		t.Fatalf("stats = %+v (notes %v)", st, notes)
	}
	s1 := data(rowByID(m.Rows["vault.secrets"], "id", "s-1"))
	if f := data(rowByID(m.Rows["vault.folders"], "id", s1["folderId"].(string))); f["name"] != "Virtualisation" || f["parentId"] != "f-root" {
		t.Fatalf("a new folder goes under the given parent: %v", f)
	}
}

func TestPlanFromTSVRefusals(t *testing.T) {
	r, err := Map(remapFixture(t), Context{Now: time.Now(), Actor: "system:sneakers-migrate"})
	if err != nil {
		t.Fatal(err)
	}
	head := "current_folder\tcurrent_name\tcurrent_type\tnew_folder\tnew_name\tnew_type\taction\n"
	for name, c := range map[string]struct{ body, owner, want string }{
		"missing secret": {head + "ESXI\tnope\tPassword\tESXI\tnope\tPassword\tcarry\n", "", "no secret"},
		"bad action":     {head + "ESXI\tesx01 root\tWeb Password\tESXI\tx\tWeb Password\tmaybe\n", "", "action"},
		"bad header":     {"a\tb\n", "", "header"},
		"personal owner": {head + "Personal\tmy key\tPassword\tPersonal\tmy key\tPassword\tcarry\n", "", "2 secrets"},
	} {
		if _, _, err := PlanFromTSV(strings.NewReader(c.body), r, Path{"Infrastructure"}, c.owner, nil); !errors.Is(err, ErrMapping) || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
