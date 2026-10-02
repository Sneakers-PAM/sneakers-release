// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package mapping

import (
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
)

func add(t *testing.T, b *bundle.Bundle, stream string, rows ...string) {
	t.Helper()
	s := b.Stream(stream)
	for _, r := range rows {
		if err := s.AddRaw([]byte(r)); err != nil {
			t.Fatal(err)
		}
	}
}

func fixture(t *testing.T) *bundle.Bundle {
	t.Helper()
	b := bundle.New("test")
	add(t, b, "identity.users",
		`{"id":"usr-1","keycloak_subject":"old-1","email":"a@example.org"}`,
		`{"id":"usr-2","keycloak_subject":"stale","email":"b@example.org"}`,
		`{"id":"usr-3","keycloak_subject":"","email":"c@example.org"}`)
	add(t, b, "workflow.approval_requests",
		`{"id":"req-1","status":1,"secret_id":"sec-1","requested_by_user_id":"usr-1","resolved_at":"","resolved_by_user_id":""}`,
		`{"id":"req-2","status":2,"secret_id":"sec-2","requested_by_user_id":"usr-1","resolved_at":"2026-01-01T00:00:00Z","resolved_by_user_id":"usr-3"}`)
	add(t, b, "workflow.approval_comments", `{"id":"cmt-1","request_id":"req-2","author_user_id":"usr-1","body":"ok","created_at":"2026-01-01T00:00:00Z"}`)
	add(t, b, "workflow.leases",
		`{"id":"lease-1","secret_id":"sec-1","user_id":"usr-1","issued_at":"2026-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","returned":false}`,
		`{"id":"lease-2","secret_id":"sec-1","user_id":"usr-1","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T08:00:00Z","returned":true}`)
	add(t, b, "vault.secret_uses",
		`{"id":"use-1","user_id":"usr-1","state":1,"expires_at":"2099-01-01T00:00:00+00:00","data":{"id":"use-1","state":"SECRET_USE_STATE_PENDING"}}`,
		`{"id":"use-2","user_id":"usr-1","state":4,"expires_at":"2099-01-01T00:00:00+00:00","data":{"id":"use-2","state":"SECRET_USE_STATE_REDEEMED"}}`)
	add(t, b, "vault.rotation_schedule",
		`{"secret_id":"sec-1","claimed_until":"2099-01-01T00:00:00+00:00","state":4,"reason":""}`,
		`{"secret_id":"sec-2","claimed_until":null,"state":1,"reason":""}`)
	add(t, b, "vault.heartbeat_schedule", `{"secret_id":"sec-1","claimed_until":"2099-01-01T00:00:00+00:00"}`)
	add(t, b, "vault.security_settings", `{"id":1,"data":{"kekRotationDays":90,"sessionTtlSeconds":1800}}`)
	add(t, b, "vault.connections", `{"id":"conn-ssh","data":{"id":"conn-ssh","protocol":"ssh"}}`, `{"id":"conn-ldap","data":{"id":"conn-ldap","protocol":"ldap"}}`)
	add(t, b, "vault.targets", `{"id":"tgt-2","data":{"id":"tgt-2","connectionId":"conn-ssh"}}`, `{"id":"tgt-1","data":{"id":"tgt-1","connectionId":"conn-ssh"}}`, `{"id":"tgt-3","data":{"id":"tgt-3","connectionId":"conn-ldap"}}`)
	return b
}

func TestMap(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	r, err := Map(fixture(t), Context{Now: now, Actor: "system:sneakers-migrate", KratosIDs: map[string]string{"old-1": "new-1"}})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	users := r.Rows["identity.users"]
	if users[0]["subject"] != "new-1" || users[1]["subject"] != "" || users[2]["subject"] != "" {
		t.Fatalf("subjects = %v / %v / %v", users[0]["subject"], users[1]["subject"], users[2]["subject"])
	}
	if _, ok := users[0]["keycloak_subject"]; ok {
		t.Fatal("keycloak_subject must not reach the target")
	}
	if len(r.Unlinked) != 2 || r.Unlinked[0] != "usr-2" || r.Unlinked[1] != "usr-3" {
		t.Fatalf("Unlinked = %v", r.Unlinked)
	}

	req := r.Rows["workflow.approval_requests"]
	if num(req[0]["status"]) != approvalDenied || req[0]["resolved_by_user_id"] != "system:sneakers-migrate" || req[0]["resolved_at"] != "2026-10-02T12:00:00Z" {
		t.Fatalf("open request not closed: %v", req[0])
	}
	if num(req[1]["status"]) != 2 || req[1]["resolved_by_user_id"] != "usr-3" {
		t.Fatalf("resolved request changed: %v", req[1])
	}
	cm := r.Rows["workflow.approval_comments"]
	if len(cm) != 2 || cm[1]["request_id"] != "req-1" || cm[1]["body"] != closedByMigration {
		t.Fatalf("comments = %v", cm)
	}
	ls := r.Rows["workflow.leases"]
	if ls[0]["returned"] != true || ls[0]["expires_at"] != "2026-10-02T12:00:00Z" {
		t.Fatalf("open lease not returned: %v", ls[0])
	}
	if ls[1]["expires_at"] != "2026-01-01T08:00:00Z" {
		t.Fatalf("returned lease changed: %v", ls[1])
	}

	uses := r.Rows["vault.secret_uses"]
	if num(uses[0]["state"]) != useStateExpired || uses[0]["data"].(map[string]any)["state"] != expiredUseName {
		t.Fatalf("pending use not expired: %v", uses[0])
	}
	if num(uses[1]["state"]) != 4 {
		t.Fatalf("redeemed use changed: %v", uses[1])
	}
	rot := r.Rows["vault.rotation_schedule"]
	if rot[0]["claimed_until"] != nil || num(rot[0]["state"]) != rotationFailed || rot[0]["reason"] != "interrupted by migration" {
		t.Fatalf("rotation claim not cleared: %v", rot[0])
	}
	if r.Rows["vault.heartbeat_schedule"][0]["claimed_until"] != nil {
		t.Fatal("heartbeat claim not cleared")
	}
	if got := r.Rows["vault.security_settings"][0]["data"].(map[string]any)["kekRotationDays"]; got == 0 {
		t.Fatal("cutover mode must keep the KEK rotation setting")
	}
	if len(r.SSHTargets) != 2 || r.SSHTargets[0] != "tgt-1" || r.SSHTargets[1] != "tgt-2" {
		t.Fatalf("SSHTargets = %v", r.SSHTargets)
	}
	want := map[string]int{"approval requests": 1, "check-outs": 1, "secret uses": 1, "rotation claims": 1, "heartbeat claims": 1}
	for k, v := range want {
		if r.Closed[k] != v {
			t.Fatalf("Closed[%s] = %d, want %d (all: %v)", k, r.Closed[k], v, r.Closed)
		}
	}
	actions := map[string]int{}
	for _, e := range r.Events {
		actions[e.Action]++
	}
	for _, a := range []string{"workflow.request.expired_by_migration", "workflow.lease.returned_by_migration", "secret.use.expired_by_migration", "secret.rotation.interrupted_by_migration"} {
		if actions[a] != 1 {
			t.Fatalf("events = %v, want one %s", actions, a)
		}
	}
	if r.Expected()["workflow.approval_comments"] != 2 {
		t.Fatal("Expected must count the added comment")
	}
}

func TestRehearsalTurnsKEKRotationOff(t *testing.T) {
	r, err := Map(fixture(t), Context{Now: time.Now(), Actor: "system:sneakers-migrate", Rehearsal: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Rows["vault.security_settings"][0]["data"].(map[string]any)["kekRotationDays"]; got != 0 {
		t.Fatalf("kekRotationDays = %v, want 0 in rehearsal", got)
	}
}
