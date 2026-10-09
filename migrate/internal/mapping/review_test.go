// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package mapping

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestReviewListsNamesOnlyAndMakesATemplate(t *testing.T) {
	r, err := Map(remapFixture(t), Context{Now: time.Now(), Actor: "system:sneakers-migrate"})
	if err != nil {
		t.Fatal(err)
	}
	rv, err := Review(r)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(rv.Secrets) != 6 || rv.ByType["Password"] != 4 || rv.ByFolder["Infrastructure / ESXI"] != 2 {
		t.Fatalf("review = %+v", rv)
	}
	var pki, mine Item
	for _, it := range rv.Secrets {
		switch it.ID {
		case "s-3":
			pki = it
		case "s-5":
			mine = it
		}
	}
	if strings.Join(pki.Folder, "|") != "Infrastructure|Certs/PKI" || pki.Type != "Windows Domain Account" {
		t.Fatalf("s-3 = %+v", pki)
	}
	if mine.Owner != "owner@example.org" || strings.Join(mine.Folder, "|") != "Personal|Personal" {
		t.Fatalf("s-5 = %+v", mine)
	}
	raw, err := json.Marshal(rv)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	if err := rv.Text(&text); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw)+text.String(), "pw-") {
		t.Fatal("the review carries a secret value")
	}

	tpl, err := json.Marshal(rv.Template("b-1"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(tpl), "pw-") {
		t.Fatal("the template carries a secret value")
	}
	p, err := ParsePlan(tpl)
	if err != nil {
		t.Fatalf("the template doesn't parse as a mapping file: %v", err)
	}
	again, err := Map(remapFixture(t), Context{Now: time.Now(), Actor: "system:sneakers-migrate", Plan: p})
	if err != nil {
		t.Fatalf("the unedited template doesn't apply: %v", err)
	}
	if st := again.Remap; st.SecretsMoved+st.SecretsRenamed+st.SecretsRetyped+st.SecretsDropped+st.SecretsKept != 0 {
		t.Fatalf("the unedited template changed something: %+v", st)
	}
}
