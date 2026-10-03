// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package settings reviews the imported security settings against the target
// vault's defaults. The original system stored the sensitive-data switches but
// never enforced them; the target does, so importing the stored values can
// restrict what tokens and people could do before. The review lists every
// setting and warns, with counts, on each one that will now restrict
// something, so the owner can adjust it before cutover.
package settings

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/report"
)

// The target vault's defaults (what first-run setup installs) and the
// gateway's session clamp.
const (
	defaultPasswordPolicy = "pwpolicy-default"
	defaultRetentionDays  = 90
	defaultSessionTTL     = 1800
	defaultKEKDays        = 90
	minSessionTTL         = 900
	maxSessionTTL         = 3600
)

// Folder.reveal_step_up, as protojson writes it (name) or a raw number.
const (
	stepUpRequire = "STEP_UP_MODE_REQUIRE"
	stepUpOff     = "STEP_UP_MODE_OFF"
)

// Review lists each imported security setting next to its new default and
// warns on the ones the target now enforces in a restricting way. rows are
// the mapped rows, so what is reviewed is what is written.
func Review(rows map[string][]mapping.Row) report.Security {
	set := map[string]any{}
	if r := rows["vault.security_settings"]; len(r) > 0 {
		set = data(r[0])
	}
	allowAPI := boolOf(set["allowApiForSensitive"])
	checkoutMFA := boolOf(set["requireMfaForSensitiveCheckout"])
	revealMFA := boolOf(set["requireMfaForReveal"])

	types := map[string]map[string]any{}
	for _, r := range rows["vault.secret_types"] {
		d := data(r)
		types[str(d["id"])] = d
	}
	folders := map[string]map[string]any{}
	require, off := 0, 0
	for _, r := range rows["vault.folders"] {
		d := data(r)
		folders[str(d["id"])] = d
		switch stepUp(d["revealStepUp"]) {
		case stepUpRequire:
			require++
		case stepUpOff:
			off++
		}
	}

	var superFields, superSecrets, checkoutSecrets, stepUpSecrets int
	byOverride := false
	for _, r := range rows["vault.secrets"] {
		d := data(r)
		if boolOf(d["retired"]) {
			continue
		}
		t := types[str(d["typeId"])]
		n := superSensitive(t)
		if n > 0 {
			superFields += n
			superSecrets++
			if boolOf(t["checkout"]) {
				checkoutSecrets++
			}
		}
		on, fromFolder := revealStepUp(folders, str(d["folderId"]), revealMFA)
		if on {
			stepUpSecrets++
			byOverride = byOverride || fromFolder
		}
	}

	tokens := 0
	for _, r := range rows["identity.user_tokens"] {
		if r["revoked_at"] == nil {
			tokens++
		}
	}

	s := report.Security{Settings: []report.Setting{
		{Key: "defaultPasswordPolicyId", Name: "Default password policy", Imported: orUnset(str(set["defaultPasswordPolicyId"])), Default: defaultPasswordPolicy},
		{Key: "allowApiForSensitive", Name: "API access to super-sensitive fields", Imported: onOff(allowAPI), Default: onOff(false)},
		{Key: "requireMfaForSensitiveCheckout", Name: "Require MFA for sensitive check-out", Imported: onOff(checkoutMFA), Default: onOff(true)},
		{Key: "requireMfaForReveal", Name: "Step-up MFA before a reveal", Imported: onOff(revealMFA), Default: onOff(false)},
		{Key: "revealStepUpFolders", Name: "Folder step-up overrides", Imported: overrides(require, off), Default: "none"},
		{Key: "requestHistoryRetentionDays", Name: "Request history retention (days)", Imported: days(num(set["requestHistoryRetentionDays"]), defaultRetentionDays), Default: fmt.Sprint(defaultRetentionDays)},
		{Key: "sessionTtlSeconds", Name: "Session lifetime (seconds)", Imported: sessionTTL(num(set["sessionTtlSeconds"])), Default: fmt.Sprint(defaultSessionTTL)},
		{Key: "kekRotationDays", Name: "Working-key rotation (days)", Imported: kekDays(num(set["kekRotationDays"])), Default: fmt.Sprint(defaultKEKDays)},
	}}

	if !allowAPI && superFields > 0 {
		s.Warnings = append(s.Warnings, fmt.Sprintf(
			"API access to super-sensitive fields: off, so tokens can no longer reveal or use %s in %s; this affects %s (%s) and %s. Turn it on before cutover if automation needs them",
			plural(superFields, "super-sensitive field"), plural(superSecrets, "secret"),
			plural(len(rows["identity.service_accounts"]), "service account"), plural(len(rows["identity.api_tokens"]), "service-account token"),
			plural(tokens, "active personal token")))
	}
	if checkoutMFA && checkoutSecrets > 0 {
		s.Warnings = append(s.Warnings, fmt.Sprintf(
			"MFA for sensitive check-out: on, so checking out %s whose type has a super-sensitive field now needs an MFA within MFA_MAX_AGE",
			plural(checkoutSecrets, "secret")))
	}
	if stepUpSecrets > 0 {
		var why []string
		if revealMFA {
			why = append(why, "the global setting")
		}
		if byOverride || (!revealMFA && require > 0) {
			why = append(why, plural(require, "folder override"))
		}
		s.Warnings = append(s.Warnings, fmt.Sprintf(
			"Step-up MFA before a reveal: on for %s (from %s), so people need a fresh MFA to reveal or copy them",
			plural(stepUpSecrets, "secret"), strings.Join(why, " and ")))
	}
	return s
}

// revealStepUp resolves step-up for a secret in folder id the way the vault
// does: the nearest folder that sets require or off wins, else the global
// switch. fromFolder says a folder decided it.
func revealStepUp(folders map[string]map[string]any, id string, global bool) (on, fromFolder bool) {
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		seen[id] = true
		f, ok := folders[id]
		if !ok {
			break
		}
		switch stepUp(f["revealStepUp"]) {
		case stepUpRequire:
			return true, true
		case stepUpOff:
			return false, true
		}
		id = str(f["parentId"])
	}
	return global, false
}

func superSensitive(t map[string]any) int {
	fields, _ := t["fields"].([]any)
	n := 0
	for _, f := range fields {
		if m, ok := f.(map[string]any); ok && boolOf(m["superSensitive"]) {
			n++
		}
	}
	return n
}

func data(r mapping.Row) map[string]any {
	switch v := r["data"].(type) {
	case map[string]any:
		return v
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(v), &m) == nil {
			return m
		}
	}
	return map[string]any{}
}

func stepUp(v any) string {
	switch fmt.Sprint(v) {
	case stepUpRequire, "1":
		return stepUpRequire
	case stepUpOff, "2":
		return stepUpOff
	}
	return ""
}

func boolOf(v any) bool { b, _ := v.(bool); return b }

func str(v any) string { s, _ := v.(string); return s }

func num(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func orUnset(s string) string {
	if s == "" {
		return "unset"
	}
	return s
}

func overrides(require, off int) string {
	if require+off == 0 {
		return "none"
	}
	return fmt.Sprintf("%d require, %d off", require, off)
}

func days(n, def int64) string {
	if n == 0 {
		return fmt.Sprintf("unset (%d)", def)
	}
	return fmt.Sprint(n)
}

func sessionTTL(n int64) string {
	switch {
	case n == 0:
		return fmt.Sprintf("unset (%d)", defaultSessionTTL)
	case n < minSessionTTL:
		return fmt.Sprintf("%d (the gateway clamps it to %d)", n, minSessionTTL)
	case n > maxSessionTTL:
		return fmt.Sprintf("%d (the gateway clamps it to %d)", n, maxSessionTTL)
	}
	return fmt.Sprint(n)
}

func kekDays(n int64) string {
	if n == 0 {
		return "off"
	}
	return fmt.Sprint(n)
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
