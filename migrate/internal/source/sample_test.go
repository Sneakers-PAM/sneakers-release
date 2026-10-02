// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"strings"
	"testing"
)

func TestSpread(t *testing.T) {
	ids := []string{"e", "a", "d", "c", "b"}
	if got := spread(ids, 2); len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("spread = %v", got)
	}
	if got := spread(ids, 0); len(got) != 5 {
		t.Fatalf("spread(0) = %v, want all", got)
	}
}

func TestSampleHMACIsKeyedAndBound(t *testing.T) {
	k1, k2 := []byte("key-one-key-one-key-one-key-one!"), []byte("key-two-key-two-key-two-key-two!")
	a := SampleHMAC(k1, "sec-1", 0, "password", "x")
	if a == SampleHMAC(k2, "sec-1", 0, "password", "x") || a == SampleHMAC(k1, "sec-1", 1, "password", "x") || a == SampleHMAC(k1, "sec-1", 0, "password", "y") {
		t.Fatal("the HMAC must depend on the key, the version and the value")
	}
	if strings.Contains(a, "x") && len(a) != 64 {
		t.Fatal("want a hex sha256 HMAC")
	}
}
