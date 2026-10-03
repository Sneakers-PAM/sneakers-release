// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
)

func rows(settings map[string]any) map[string][]mapping.Row {
	cardType := map[string]any{"id": "type-card", "checkout": true, "fields": []any{
		map[string]any{"key": "number", "superSensitive": true},
		map[string]any{"key": "cvv", "superSensitive": true},
		map[string]any{"key": "holder"},
	}}
	pwType := map[string]any{"id": "type-password", "checkout": true, "fields": []any{map[string]any{"key": "password"}}}
	secret := func(id, typ, folder string, retired bool) mapping.Row {
		d := map[string]any{"id": id, "typeId": typ, "folderId": folder}
		if retired {
			d["retired"] = true
		}
		return mapping.Row{"id": id, "data": d}
	}
	folder := func(id, parent, mode string) mapping.Row {
		d := map[string]any{"id": id, "parentId": parent}
		if mode != "" {
			d["revealStepUp"] = mode
		}
		return mapping.Row{"id": id, "data": d}
	}
	return map[string][]mapping.Row{
		"vault.security_settings": {{"id": 1, "data": settings}},
		"vault.secret_types":      {{"id": "type-card", "data": cardType}, {"id": "type-password", "data": pwType}},
		"vault.folders": {
			folder("f-fin", "", "STEP_UP_MODE_REQUIRE"), folder("f-fin-cards", "f-fin", ""),
			folder("f-lab", "", "STEP_UP_MODE_OFF"), folder("f-ops", "", ""),
		},
		"vault.secrets": {
			secret("s1", "type-card", "f-fin-cards", false), secret("s2", "type-card", "f-ops", false),
			secret("s3", "type-card", "f-ops", true), secret("s4", "type-password", "f-fin", false),
			secret("s5", "type-password", "f-lab", false),
		},
		"identity.service_accounts": {{"id": "sa-1"}, {"id": "sa-2"}},
		"identity.api_tokens":       {{"id": "tok-1"}, {"id": "tok-2"}, {"id": "tok-3"}},
		"identity.user_tokens":      {{"id": "utk-1"}, {"id": "utk-2", "revoked_at": "2026-09-01T00:00:00Z"}},
	}
}

func find(t *testing.T, s report.Security, key string) report.Setting {
	t.Helper()
	for _, x := range s.Settings {
		if x.Key == key {
			return x
		}
	}
	t.Fatalf("no setting %s in %+v", key, s.Settings)
	return report.Setting{}
}

func warning(s report.Security, prefix string) string {
	for _, w := range s.Warnings {
		if strings.HasPrefix(w, prefix) {
			return w
		}
	}
	return ""
}

// The original system stored these switches but ignored them; each one the
// target now enforces is listed with its default and warned on with counts.
func TestReviewWarnsWhereTheTargetNowRestricts(t *testing.T) {
	s := Review(rows(map[string]any{
		"defaultPasswordPolicyId": "pwpolicy-strong", "requireMfaForSensitiveCheckout": true,
		"sessionTtlSeconds": float64(7200), "kekRotationDays": float64(0),
	}))

	want := map[string][2]string{
		"defaultPasswordPolicyId":        {"pwpolicy-strong", "pwpolicy-default"},
		"allowApiForSensitive":           {"off", "off"},
		"requireMfaForSensitiveCheckout": {"on", "on"},
		"requireMfaForReveal":            {"off", "off"},
		"revealStepUpFolders":            {"1 require, 1 off", "none"},
		"requestHistoryRetentionDays":    {"unset (90)", "90"},
		"sessionTtlSeconds":              {"7200 (the gateway clamps it to 3600)", "1800"},
		"kekRotationDays":                {"off", "90"},
	}
	if len(s.Settings) != len(want) {
		t.Fatalf("got %d settings, want %d: %+v", len(s.Settings), len(want), s.Settings)
	}
	for key, v := range want {
		got := find(t, s, key)
		if got.Imported != v[0] || got.Default != v[1] || got.Name == "" {
			t.Errorf("%s = %q / %q (%q), want %q / %q", key, got.Imported, got.Default, got.Name, v[0], v[1])
		}
	}

	api := warning(s, "API access to super-sensitive fields: off")
	for _, part := range []string{"4 super-sensitive fields in 2 secrets", "2 service accounts", "3 service-account tokens", "1 active personal token"} {
		if !strings.Contains(api, part) {
			t.Errorf("API warning %q lacks %q", api, part)
		}
	}
	if w := warning(s, "MFA for sensitive check-out: on"); !strings.Contains(w, "2 secrets") {
		t.Errorf("check-out warning = %q, want 2 secrets (the retired one doesn't count)", w)
	}
	if w := warning(s, "Step-up MFA before a reveal:"); !strings.Contains(w, "2 secrets") || !strings.Contains(w, "1 folder override") {
		t.Errorf("step-up warning = %q, want 2 secrets from 1 folder override", w)
	}
	if len(s.Warnings) != 3 {
		t.Errorf("got %d warnings, want 3: %q", len(s.Warnings), s.Warnings)
	}
}

// With API access on, check-out MFA off and no step-up anywhere, nothing is
// newly restricted, so there is nothing to warn about.
func TestReviewIsQuietWhenNothingIsRestricted(t *testing.T) {
	r := rows(map[string]any{"allowApiForSensitive": true})
	r["vault.folders"] = nil
	s := Review(r)
	if len(s.Warnings) != 0 {
		t.Fatalf("warnings = %q, want none", s.Warnings)
	}
	if got := find(t, s, "requireMfaForSensitiveCheckout"); got.Imported != "off" || got.Default != "on" {
		t.Fatalf("check-out MFA = %+v", got)
	}
}

// The global step-up switch applies to every live secret no folder turns
// off: s1, s2 and s4, not s5 (under the off override) or s3 (retired, which
// the vault won't reveal anyway).
func TestReviewCountsGlobalStepUp(t *testing.T) {
	s := Review(rows(map[string]any{"allowApiForSensitive": true, "requireMfaForReveal": true}))
	w := warning(s, "Step-up MFA before a reveal:")
	if !strings.Contains(w, "3 secrets") || !strings.Contains(w, "the global setting") {
		t.Fatalf("step-up warning = %q, want 3 secrets from the global setting", w)
	}
}
