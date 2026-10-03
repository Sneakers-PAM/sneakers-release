// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package chain recomputes and checks the audit service's hash chain. Each
// record's hash is the hex sha256 of its canonical form, which covers the
// previous record's hash, so an edit, a deletion or a reorder breaks every
// later hash. Imported records keep their stored hashes; this package only
// checks them.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Record is one audit record as the audit_records table stores it.
type Record struct {
	Seq         uint64            `json:"seq"`
	Tier        int32             `json:"tier"`
	Action      string            `json:"action"`
	ActorUserID string            `json:"actor_user_id"`
	Subject     string            `json:"subject"`
	GroupID     string            `json:"group_id"`
	Sensitive   bool              `json:"sensitive"`
	Attributes  map[string]string `json:"attributes"`
	OccurredAt  string            `json:"occurred_at"`
	PrevHash    string            `json:"prev_hash"`
	Hash        string            `json:"hash"`
}

var tierNames = map[int32]string{0: "TIER_UNSPECIFIED", 1: "TIER_AUDIT", 2: "TIER_ACTIVITY"}

// TierName is the tier's enum name as the audit service hashes it; an unknown
// value hashes as its number.
func TierName(t int32) string {
	if n, ok := tierNames[t]; ok {
		return n
	}
	return strconv.FormatInt(int64(t), 10)
}

// Canonical is the byte form that gets hashed: the fields joined by "|", with
// the attributes sorted by key as "k=v;" pairs and the record's own hash left
// out.
func Canonical(r Record) string {
	keys := make([]string, 0, len(r.Attributes))
	for k := range r.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var attrs strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&attrs, "%s=%s;", k, r.Attributes[k])
	}
	return strings.Join([]string{
		strconv.FormatUint(r.Seq, 10),
		TierName(r.Tier),
		r.Action,
		r.ActorUserID,
		r.Subject,
		r.GroupID,
		strconv.FormatBool(r.Sensitive),
		attrs.String(),
		r.OccurredAt,
		r.PrevHash,
	}, "|")
}

// Hash is the hex sha256 of the record's canonical form.
func Hash(r Record) string {
	sum := sha256.Sum256([]byte(Canonical(r)))
	return hex.EncodeToString(sum[:])
}

// Verify checks a chain from genesis: seq runs 1, 2, 3..., each prev_hash is
// the previous hash (empty for the first), and each stored hash recomputes.
// It returns the seq of the first bad record, or 0 when the chain is valid.
func Verify(recs []Record) (bool, uint64) { return verifyFrom(1, "", recs) }

// VerifyFrom checks a chain segment that continues after a record whose hash
// is prev.
func VerifyFrom(prev string, recs []Record) (bool, uint64) {
	if len(recs) == 0 {
		return true, 0
	}
	return verifyFrom(recs[0].Seq, prev, recs)
}

func verifyFrom(first uint64, prev string, recs []Record) (bool, uint64) {
	for i, r := range recs {
		if r.Seq != first+uint64(i) || r.PrevHash != prev || Hash(r) != r.Hash {
			return false, r.Seq
		}
		prev = r.Hash
	}
	return true, 0
}
