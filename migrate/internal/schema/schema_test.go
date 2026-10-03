// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import "testing"

func TestEveryTableHasAKeyAndAUniqueStream(t *testing.T) {
	seen := map[string]bool{}
	for _, tb := range append(append([]Table{}, Tables...), TargetOnly...) {
		if len(tb.Key) == 0 {
			t.Fatalf("%s has no key", tb.Stream())
		}
		if seen[tb.Stream()] {
			t.Fatalf("%s listed twice", tb.Stream())
		}
		seen[tb.Stream()] = true
	}
	for _, s := range Services {
		if len(Of(s)) == 0 {
			t.Fatalf("service %s has no tables", s)
		}
		if _, ok := SourceProfile.Versions[s]; !ok {
			t.Fatalf("source profile lacks %s", s)
		}
	}
}

func TestCarriedAndLookup(t *testing.T) {
	for stream, want := range map[string]bool{
		"vault.kek_keyring": false, "identity.user_email_otp": false, "identity.webauthn_sessions": false,
		"vault.secret_versions": true, "identity.users": true, "audit.audit_records": true,
	} {
		tb, ok := Lookup(stream)
		if !ok {
			t.Fatalf("Lookup(%s) failed", stream)
		}
		if tb.Carried() != want {
			t.Fatalf("%s Carried = %v, want %v", stream, tb.Carried(), want)
		}
	}
	if _, ok := Lookup("vault.nope"); ok {
		t.Fatal("unknown stream found")
	}
}
