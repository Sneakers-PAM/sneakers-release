// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package mapping

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
)

func remapFixture(t *testing.T) *bundle.Bundle {
	t.Helper()
	b := bundle.New("test")
	add(t, b, "identity.users",
		`{"id":"usr-1","keycloak_subject":"","email":"Owner@example.org"}`,
		`{"id":"usr-2","keycloak_subject":"","email":"other@example.org"}`)
	add(t, b, "vault.secret_types",
		`{"id":"type-pw","data":{"id":"type-pw","name":"Password","rotation":true,"fields":[{"key":"username"},{"key":"password"},{"key":"notes"}]}}`,
		`{"id":"type-web","data":{"id":"type-web","name":"Web Password","fields":[{"key":"username"},{"key":"password"},{"key":"url"}]}}`,
		`{"id":"type-legacy","data":{"id":"type-legacy","name":"Windows Domain Account","fields":[{"key":"user"},{"key":"pass"},{"key":"comment"}]}}`,
		`{"id":"type-ad","data":{"id":"type-ad","name":"Active Directory Account","rotation":true,"heartbeat":true,"fields":[{"key":"domain"},{"key":"username"},{"key":"password"}]}}`)
	add(t, b, "vault.folders",
		`{"id":"f-root","data":{"id":"f-root","name":"Infrastructure"}}`,
		`{"id":"f-esx","data":{"id":"f-esx","name":"ESXI","parentId":"f-root"}}`,
		`{"id":"f-pki","data":{"id":"f-pki","name":"Certs/PKI","parentId":"f-root"}}`,
		`{"id":"f-old","data":{"id":"f-old","name":"Retired stuff"}}`,
		`{"id":"f-proot","data":{"id":"f-proot","name":"Personal","isMasterPersonal":true,"scope":"FOLDER_SCOPE_PERSONAL"}}`,
		`{"id":"f-p1","data":{"id":"f-p1","name":"Personal","parentId":"f-proot","scope":"FOLDER_SCOPE_PERSONAL","ownerUserId":"usr-1"}}`,
		`{"id":"f-p2","data":{"id":"f-p2","name":"Personal","parentId":"f-proot","scope":"FOLDER_SCOPE_PERSONAL","ownerUserId":"usr-2"}}`)
	add(t, b, "vault.folder_rules", `{"id":"fr-1","data":{"id":"fr-1","folderId":"f-old"}}`, `{"id":"fr-2","data":{"id":"fr-2","folderId":"f-esx"}}`)
	add(t, b, "vault.raci_rules", `{"id":"raci-1","data":{"id":"raci-1","folderId":"f-old"}}`)
	add(t, b, "vault.secrets",
		`{"id":"s-1","data":{"id":"s-1","name":"esx01 root","typeId":"type-web","folderId":"f-esx","position":1}}`,
		`{"id":"s-2","data":{"id":"s-2","name":"esx02 root","typeId":"type-pw","folderId":"f-esx","position":2,"rotationIntervalDays":30}}`,
		`{"id":"s-3","data":{"id":"s-3","name":"svc account","typeId":"type-legacy","folderId":"f-pki","position":1}}`,
		`{"id":"s-4","data":{"id":"s-4","name":"old thing","typeId":"type-pw","folderId":"f-old","position":1}}`,
		`{"id":"s-5","data":{"id":"s-5","name":"my key","typeId":"type-pw","folderId":"f-p1","position":1}}`,
		`{"id":"s-6","data":{"id":"s-6","name":"my key","typeId":"type-pw","folderId":"f-p2","position":1}}`)
	add(t, b, "vault.secret_records",
		`{"secret_id":"s-1","fields":{"username":"root","password":"pw-one-aaaa","url":"https://esx01.example.org"}}`,
		`{"secret_id":"s-2","fields":{"username":"root","password":"pw-two-bbbb"}}`,
		`{"secret_id":"s-3","fields":{"user":"svc","pass":"pw-three-cc","comment":""}}`,
		`{"secret_id":"s-4","fields":{"password":"pw-four-ddd"}}`,
		`{"secret_id":"s-5","fields":{"password":"pw-five-eee"}}`,
		`{"secret_id":"s-6","fields":{"password":"pw-six-ffff"}}`)
	add(t, b, "vault.secret_versions",
		`{"secret_id":"s-3","version_no":1,"active":true,"created_at":"2026-01-01T00:00:00Z","fields":{"user":"svc","pass":"pw-three-cc","comment":""}}`,
		`{"secret_id":"s-4","version_no":1,"active":true,"created_at":"2026-01-01T00:00:00Z","fields":{"password":"pw-four-ddd"}}`)
	add(t, b, "vault.rotation_schedule", `{"secret_id":"s-2","claimed_until":null,"state":1}`, `{"secret_id":"s-4","claimed_until":null,"state":1}`)
	add(t, b, "vault.secret_uses", `{"id":"use-1","user_id":"usr-1","state":4,"data":{"id":"use-1","secretId":"s-4"}}`)
	add(t, b, "vault.secret_use_grants", `{"id":"g-1","user_id":"usr-1","data":{"id":"g-1","secretIds":["s-4","s-1"]}}`, `{"id":"g-2","user_id":"usr-1","data":{"id":"g-2","secretIds":["s-4"]}}`)
	add(t, b, "vault.connections", `{"id":"conn-1","data":{"id":"conn-1","protocol":"ldap","privilegedSecretId":"s-3"}}`)
	add(t, b, "workflow.approval_requests", `{"id":"req-1","status":2,"secret_id":"s-4"}`, `{"id":"req-2","status":2,"secret_id":"s-1"}`)
	add(t, b, "workflow.approval_comments", `{"id":"cmt-1","request_id":"req-1"}`, `{"id":"cmt-2","request_id":"req-2"}`)
	add(t, b, "workflow.leases", `{"id":"lease-1","secret_id":"s-4","returned":true,"expires_at":"2026-01-01T00:00:00Z"}`)
	return b
}

func plan(t *testing.T, body string) *Plan {
	t.Helper()
	p, err := ParsePlan([]byte(body))
	if err != nil {
		t.Fatalf("ParsePlan: %v", err)
	}
	return p
}

func mapWith(t *testing.T, p *Plan) (*Result, error) {
	t.Helper()
	return Map(remapFixture(t), Context{Now: time.Now(), Actor: "system:sneakers-migrate", Plan: p})
}

func rowByID(rows []Row, col, id string) Row {
	for _, r := range rows {
		if fmt.Sprint(r[col]) == id {
			return r
		}
	}
	return nil
}

func data(r Row) map[string]any { return r["data"].(map[string]any) }

const fullPlan = `{
  "format": "sneakers-migrate-mapping", "version": 1, "unlisted": "keep",
  "folders": [
    {"from": ["Infrastructure", "Certs/PKI"], "to": "Infrastructure/Directory/PKI"},
    {"from": "Retired stuff", "drop": true}
  ],
  "types": [
    {"from": "Windows Domain Account", "to": "Active Directory Account", "fields": {"user": "username", "pass": "password"}}
  ],
  "secrets": [
    {"from": {"folder": "Infrastructure/ESXI", "name": "esx01 root", "type": "Web Password"},
     "to": {"folder": "Infrastructure/Virtualisation/ESXi", "name": "esx01 - root (lab)"}},
    {"id": "s-3", "from": {"name": "svc account"}, "to": {"type": "Active Directory Account"}},
    {"from": {"folder": "Retired stuff", "name": "old thing"}, "drop": true},
    {"from": {"folder": "Personal/Personal", "owner": "owner@example.org", "name": "my key"}, "to": {"name": "my laptop key"}}
  ]
}`

func TestPlanRemapsFoldersNamesAndTypes(t *testing.T) {
	r, err := mapWith(t, plan(t, fullPlan))
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	st := r.Remap
	if st.FoldersMoved != 1 || st.FoldersCreated != 3 || st.FoldersDropped != 1 || st.SecretsMoved != 1 || st.SecretsRenamed != 2 || st.SecretsRetyped != 1 || st.SecretsDropped != 1 || st.SecretsKept != 2 {
		t.Fatalf("stats = %+v", st)
	}
	if len(st.MappingSHA256) != 64 {
		t.Fatalf("mapping hash %q", st.MappingSHA256)
	}

	// The moved folder keeps its id; its new parent is created once, with an
	// id derived from its path.
	pki := data(rowByID(r.Rows["vault.folders"], "id", "f-pki"))
	if pki["name"] != "PKI" || !strings.HasPrefix(fmt.Sprint(pki["parentId"]), "folder-mig-") {
		t.Fatalf("moved folder = %v", pki)
	}
	again, err := mapWith(t, plan(t, fullPlan))
	if err != nil {
		t.Fatal(err)
	}
	if data(rowByID(again.Rows["vault.folders"], "id", "f-pki"))["parentId"] != pki["parentId"] {
		t.Fatal("a created folder's id must be the same on every run, so verify maps as import did")
	}

	s1 := data(rowByID(r.Rows["vault.secrets"], "id", "s-1"))
	esxi := data(rowByID(r.Rows["vault.folders"], "id", fmt.Sprint(s1["folderId"])))
	if s1["name"] != "esx01 - root (lab)" || esxi["name"] != "ESXi" || s1["position"] != 1 {
		t.Fatalf("s-1 = %v in %v", s1, esxi)
	}
	if s2 := data(rowByID(r.Rows["vault.secrets"], "id", "s-2")); s2["position"] != 1 || s2["folderId"] != "f-esx" {
		t.Fatalf("the secret left behind in ESXI must close the gap: %v", s2)
	}

	s3 := data(rowByID(r.Rows["vault.secrets"], "id", "s-3"))
	if s3["typeId"] != "type-ad" {
		t.Fatalf("s-3 type = %v", s3["typeId"])
	}
	for _, stream := range []string{"vault.secret_records", "vault.secret_versions"} {
		f := rowByID(r.Rows[stream], "secret_id", "s-3")["fields"].(map[string]any)
		if f["username"] != "svc" || f["password"] != "pw-three-cc" || len(f) != 2 {
			t.Fatalf("%s s-3 fields = %v", stream, f)
		}
	}

	if rowByID(r.Rows["vault.secrets"], "id", "s-4") != nil || rowByID(r.Rows["vault.secret_records"], "secret_id", "s-4") != nil ||
		rowByID(r.Rows["vault.secret_versions"], "secret_id", "s-4") != nil || rowByID(r.Rows["vault.rotation_schedule"], "secret_id", "s-4") != nil ||
		len(r.Rows["vault.secret_uses"]) != 0 || len(r.Rows["workflow.leases"]) != 0 {
		t.Fatal("a dropped secret left rows behind")
	}
	if len(r.Rows["vault.secret_use_grants"]) != 1 || fmt.Sprint(data(r.Rows["vault.secret_use_grants"][0])["secretIds"]) != "[s-1]" {
		t.Fatalf("grants = %v", r.Rows["vault.secret_use_grants"])
	}
	if len(r.Rows["workflow.approval_requests"]) != 1 || len(r.Rows["workflow.approval_comments"]) != 1 {
		t.Fatal("the dropped secret's approval requests and their comments must go")
	}
	if rowByID(r.Rows["vault.folders"], "id", "f-old") != nil || len(r.Rows["vault.raci_rules"]) != 0 || len(r.Rows["vault.folder_rules"]) != 1 {
		t.Fatal("a dropped folder left its rows or rules behind")
	}
	dropped := 0
	for _, e := range r.Events {
		if e.Action == "secret.dropped_by_migration" && e.Subject == "s-4" {
			dropped++
		}
	}
	if dropped != 1 {
		t.Fatalf("events = %v, want one drop entry for s-4", r.Events)
	}

	if s5 := data(rowByID(r.Rows["vault.secrets"], "id", "s-5")); s5["name"] != "my laptop key" {
		t.Fatalf("the owner's personal secret = %v", s5)
	}
	if s6 := data(rowByID(r.Rows["vault.secrets"], "id", "s-6")); s6["name"] != "my key" {
		t.Fatalf("another user's personal secret changed: %v", s6)
	}
}

func TestPlanRefusals(t *testing.T) {
	head := `"format": "sneakers-migrate-mapping", "version": 1, "unlisted": "keep"`
	cases := []struct{ name, body, want string }{
		{"unlisted refused", `{"format": "sneakers-migrate-mapping", "version": 1, "unlisted": "refuse"}`, "not in the mapping file"},
		{"ambiguous personal", `{` + head + `, "secrets": [{"from": {"name": "my key"}, "to": {"name": "x"}}]}`, "2 secrets match"},
		{"no such secret", `{` + head + `, "secrets": [{"from": {"folder": "Infrastructure/ESXI", "name": "nope"}, "drop": true}]}`, "no secret"},
		{"id names disagree", `{` + head + `, "secrets": [{"id": "s-1", "from": {"name": "something else"}, "drop": true}]}`, "is not"},
		{"twice", `{` + head + `, "secrets": [{"id": "s-1", "from": {}, "drop": true}, {"from": {"name": "esx01 root"}, "drop": true}]}`, "already re-mapped"},
		{"field lost", `{` + head + `, "secrets": [{"id": "s-3", "from": {}, "to": {"type": "Web Password"}}]}`, "has no place"},
		{"privileged secret dropped", `{` + head + `, "secrets": [{"id": "s-3", "from": {}, "drop": true}]}`, "privileged account"},
		{"folder not empty", `{` + head + `, "folders": [{"from": "Retired stuff", "drop": true}]}`, "still holds secret"},
		{"no such folder", `{` + head + `, "folders": [{"from": "Nowhere", "to": "Elsewhere"}]}`, "no folder"},
		{"personal into shared", `{` + head + `, "folders": [{"from": "Personal/Personal", "owner": "owner@example.org", "to": "Infrastructure/Mine"}]}`, "can't move into a shared"},
		{"into itself", `{` + head + `, "folders": [{"from": "Infrastructure", "to": "Infrastructure/ESXI/Infrastructure"}]}`, "inside itself"},
		{"unknown type", `{` + head + `, "secrets": [{"id": "s-1", "from": {}, "to": {"type": "Nope"}}]}`, "no secret type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := mapWith(t, plan(t, c.body))
			if !errors.Is(err, ErrMapping) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want a mapping error with %q", err, c.want)
			}
			if strings.Contains(fmt.Sprint(err), "pw-") {
				t.Fatal("a mapping error carries a value")
			}
		})
	}
}

func TestParsePlanIsStrict(t *testing.T) {
	for name, body := range map[string]string{
		"format":       `{"format": "other", "version": 1, "unlisted": "keep"}`,
		"version":      `{"format": "sneakers-migrate-mapping", "version": 2, "unlisted": "keep"}`,
		"unlisted":     `{"format": "sneakers-migrate-mapping", "version": 1}`,
		"unknown key":  `{"format": "sneakers-migrate-mapping", "version": 1, "unlisted": "keep", "extra": true}`,
		"to and drop":  `{"format": "sneakers-migrate-mapping", "version": 1, "unlisted": "keep", "secrets": [{"id": "s-1", "to": {"name": "x"}, "drop": true}]}`,
		"neither":      `{"format": "sneakers-migrate-mapping", "version": 1, "unlisted": "keep", "folders": [{"from": "a"}]}`,
		"not json":     `format: yaml`,
		"no secret id": `{"format": "sneakers-migrate-mapping", "version": 1, "unlisted": "keep", "secrets": [{"from": {"folder": "a"}, "drop": true}]}`,
	} {
		if _, err := ParsePlan([]byte(body)); !errors.Is(err, ErrMapping) {
			t.Fatalf("%s: err = %v, want a mapping error", name, err)
		}
	}
}

func TestNoPlanCarriesEverything(t *testing.T) {
	r, err := Map(remapFixture(t), Context{Now: time.Now(), Actor: "system:sneakers-migrate"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Remap != nil || len(r.Rows["vault.secrets"]) != 6 || len(r.Rows["vault.folders"]) != 7 {
		t.Fatalf("remap %v, %d secrets, %d folders", r.Remap, len(r.Rows["vault.secrets"]), len(r.Rows["vault.folders"]))
	}
}
