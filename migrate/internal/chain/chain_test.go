// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func link(t *testing.T, recs []Record) []Record {
	t.Helper()
	prev := ""
	for i := range recs {
		recs[i].Seq = uint64(i + 1)
		recs[i].PrevHash = prev
		recs[i].Hash = Hash(recs[i])
		prev = recs[i].Hash
	}
	return recs
}

func TestCanonicalForm(t *testing.T) {
	r := Record{
		Seq: 7, Tier: 1, Action: "secret.reveal", ActorUserID: "user-alice", Subject: "sec-1#password",
		GroupID: "", Sensitive: true, Attributes: map[string]string{"z": "1", "a": "x=y"},
		OccurredAt: "2026-01-02T03:04:05.123Z", PrevHash: "abc",
	}
	want := "7|TIER_AUDIT|secret.reveal|user-alice|sec-1#password||true|a=x=y;z=1;|2026-01-02T03:04:05.123Z|abc"
	if got := Canonical(r); got != want {
		t.Fatalf("Canonical =\n%s\nwant\n%s", got, want)
	}
	sum := sha256.Sum256([]byte(want))
	if Hash(r) != hex.EncodeToString(sum[:]) {
		t.Fatal("Hash must be hex sha256 of the canonical form")
	}
}

func TestTierNames(t *testing.T) {
	for tier, want := range map[int32]string{0: "TIER_UNSPECIFIED", 1: "TIER_AUDIT", 2: "TIER_ACTIVITY", 9: "9"} {
		if got := TierName(tier); got != want {
			t.Fatalf("TierName(%d) = %q, want %q", tier, got, want)
		}
	}
}

func TestVerify(t *testing.T) {
	recs := link(t, []Record{
		{Tier: 2, Action: "a", Attributes: map[string]string{}},
		{Tier: 1, Action: "b", ActorUserID: "u1", Attributes: map[string]string{"k": "v"}},
		{Tier: 2, Action: "c"},
	})
	if ok, at := Verify(recs); !ok || at != 0 {
		t.Fatalf("Verify = %v, %d; want valid", ok, at)
	}
	if ok, _ := Verify(nil); !ok {
		t.Fatal("an empty chain is valid")
	}
	tampered := append([]Record(nil), recs...)
	tampered[1].Subject = "edited"
	if ok, at := Verify(tampered); ok || at != 2 {
		t.Fatalf("edited record: Verify = %v, %d; want broken at 2", ok, at)
	}
	dropped := []Record{recs[0], recs[2]}
	if ok, at := Verify(dropped); ok || at != 3 {
		t.Fatalf("dropped record: Verify = %v, %d; want broken at 3", ok, at)
	}
	relinked := append([]Record(nil), recs...)
	relinked[2].PrevHash = "nope"
	relinked[2].Hash = Hash(relinked[2])
	if ok, at := Verify(relinked); ok || at != 3 {
		t.Fatalf("relinked record: Verify = %v, %d; want broken at 3", ok, at)
	}
}

func TestVerifyFrom(t *testing.T) {
	recs := link(t, []Record{{Action: "a"}, {Action: "b"}, {Action: "c"}})
	if ok, at := VerifyFrom(recs[1].Hash, recs[2:]); !ok || at != 0 {
		t.Fatalf("VerifyFrom = %v, %d", ok, at)
	}
	if ok, at := VerifyFrom("other", recs[2:]); ok || at != 3 {
		t.Fatalf("VerifyFrom wrong prev = %v, %d", ok, at)
	}
}
