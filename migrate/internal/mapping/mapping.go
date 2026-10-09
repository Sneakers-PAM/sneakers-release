// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package mapping turns bundle rows (the source layout) into rows for the
// target baselines, and closes what can't carry over: in-flight approvals,
// check-outs, uses and rotation claims end "by migration", each with an event
// for the audit trail. Values stay in memory; nothing here logs them.
package mapping

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
)

// Row is one table row, column name to value.
type Row = map[string]any

// Context is what the mapping needs from the import.
type Context struct {
	Now   time.Time
	Actor string
	// KratosIDs maps each source Kratos identity id to the new one.
	KratosIDs map[string]string
	Rehearsal bool
	// Plan re-maps folders, names and types and drops what it says; nil
	// carries everything as it is.
	Plan *Plan
}

// Event is one migration audit entry to append after the import.
type Event struct {
	Action  string
	Subject string
	Attrs   map[string]string
}

// Result is the mapped rows plus what the report lists.
type Result struct {
	Rows map[string][]Row
	// Events are the per-item migration audit entries.
	Events []Event
	// SSHTargets need host-key pins before brokered SSH works again.
	SSHTargets []string
	// Unlinked users have no sign-in identity on the target.
	Unlinked []string
	// Closed counts what was closed by migration, by kind.
	Closed map[string]int
	// Remap is what the plan changed; nil without a plan.
	Remap *RemapStats
}

// Workflow approval statuses and vault use and rotation states, as stored.
const (
	approvalPending   = 1
	approvalDenied    = 3
	useStatePending   = 1
	useStateApproved  = 2
	useStateExpired   = 5
	rotationFailed    = 2
	rotationRotating  = 4
	expiredUseName    = "SECRET_USE_STATE_EXPIRED"
	closedByMigration = "Expired by migration."
)

// Map maps every carried stream of b.
func Map(b *bundle.Bundle, c Context) (*Result, error) {
	r := &Result{Rows: map[string][]Row{}, Closed: map[string]int{}}
	for _, t := range schema.Tables {
		if !t.Carried() {
			continue
		}
		var rows []Row
		if err := b.Each(t.Stream(), func(raw []byte) error {
			var row Row
			if err := bundle.Decode(raw, &row); err != nil {
				return fmt.Errorf("%s: %w", t.Stream(), err)
			}
			rows = append(rows, row)
			return nil
		}); err != nil {
			return nil, err
		}
		r.Rows[t.Stream()] = rows
	}
	if err := r.identity(c); err != nil {
		return nil, err
	}
	if err := r.vault(c); err != nil {
		return nil, err
	}
	r.workflow(c)
	if c.Plan != nil {
		if err := r.applyPlan(c.Plan); err != nil {
			return nil, err
		}
	}
	if err := r.placeSecrets(); err != nil {
		return nil, err
	}
	sort.Strings(r.SSHTargets)
	sort.Strings(r.Unlinked)
	return r, nil
}

func (r *Result) identity(c Context) error {
	for _, u := range r.Rows["identity.users"] {
		old, _ := u["keycloak_subject"].(string)
		delete(u, "keycloak_subject")
		u["subject"] = ""
		if nid, ok := c.KratosIDs[old]; ok && old != "" {
			u["subject"] = nid
			continue
		}
		r.Unlinked = append(r.Unlinked, fmt.Sprint(u["id"]))
	}
	return nil
}

func setJSON(row Row, col string, fn func(m map[string]any)) error {
	var m map[string]any
	switch v := row[col].(type) {
	case map[string]any:
		m = v
	case string:
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return err
		}
	default:
		return fmt.Errorf("column %s is not a JSON object", col)
	}
	fn(m)
	row[col] = m
	return nil
}

func num(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}

func (r *Result) vault(c Context) error {
	if c.Rehearsal {
		for _, s := range r.Rows["vault.security_settings"] {
			if err := setJSON(s, "data", func(m map[string]any) { m["kekRotationDays"] = 0 }); err != nil {
				return fmt.Errorf("vault.security_settings: %w", err)
			}
		}
	}
	for _, s := range r.Rows["vault.rotation_schedule"] {
		if s["claimed_until"] != nil {
			s["claimed_until"] = nil
			r.Closed["rotation claims"]++
			if num(s["state"]) == rotationRotating {
				s["state"] = rotationFailed
				s["reason"] = "interrupted by migration"
				r.Events = append(r.Events, Event{Action: "secret.rotation.interrupted_by_migration", Subject: fmt.Sprint(s["secret_id"])})
			}
		}
	}
	for _, s := range r.Rows["vault.heartbeat_schedule"] {
		if s["claimed_until"] != nil {
			s["claimed_until"] = nil
			r.Closed["heartbeat claims"]++
		}
	}
	for _, u := range r.Rows["vault.secret_uses"] {
		st := num(u["state"])
		if st != useStatePending && st != useStateApproved {
			continue
		}
		u["state"] = useStateExpired
		u["expires_at"] = c.Now.Format(time.RFC3339)
		if err := setJSON(u, "data", func(m map[string]any) {
			m["state"] = expiredUseName
			m["expiresAtUnix"] = fmt.Sprint(c.Now.Unix())
		}); err != nil {
			return fmt.Errorf("vault.secret_uses: %w", err)
		}
		r.Closed["secret uses"]++
		r.Events = append(r.Events, Event{Action: "secret.use.expired_by_migration", Subject: fmt.Sprint(u["id"]), Attrs: map[string]string{"user_id": fmt.Sprint(u["user_id"])}})
	}
	ssh := map[string]bool{}
	for _, cn := range r.Rows["vault.connections"] {
		var proto string
		if err := setJSON(cn, "data", func(m map[string]any) { proto, _ = m["protocol"].(string) }); err != nil {
			return fmt.Errorf("vault.connections: %w", err)
		}
		if proto == "ssh" {
			ssh[fmt.Sprint(cn["id"])] = true
		}
	}
	for _, t := range r.Rows["vault.targets"] {
		var conn string
		if err := setJSON(t, "data", func(m map[string]any) { conn, _ = m["connectionId"].(string) }); err != nil {
			return fmt.Errorf("vault.targets: %w", err)
		}
		if ssh[conn] {
			r.SSHTargets = append(r.SSHTargets, fmt.Sprint(t["id"]))
		}
	}
	return nil
}

func (r *Result) workflow(c Context) {
	now := c.Now.Format(time.RFC3339)
	for _, a := range r.Rows["workflow.approval_requests"] {
		if num(a["status"]) != approvalPending {
			continue
		}
		id := fmt.Sprint(a["id"])
		a["status"] = approvalDenied
		a["resolved_at"] = now
		a["resolved_by_user_id"] = c.Actor
		r.Rows["workflow.approval_comments"] = append(r.Rows["workflow.approval_comments"], Row{
			"id": "migration-" + id, "request_id": id, "author_user_id": c.Actor, "body": closedByMigration, "created_at": now,
		})
		r.Closed["approval requests"]++
		r.Events = append(r.Events, Event{Action: "workflow.request.expired_by_migration", Subject: id, Attrs: map[string]string{"secret_id": fmt.Sprint(a["secret_id"]), "requested_by": fmt.Sprint(a["requested_by_user_id"])}})
	}
	for _, l := range r.Rows["workflow.leases"] {
		if l["returned"] == true {
			continue
		}
		l["returned"] = true
		if exp, err := time.Parse(time.RFC3339, fmt.Sprint(l["expires_at"])); err != nil || exp.After(c.Now) {
			l["expires_at"] = now
		}
		r.Closed["check-outs"]++
		r.Events = append(r.Events, Event{Action: "workflow.lease.returned_by_migration", Subject: fmt.Sprint(l["id"]), Attrs: map[string]string{"secret_id": fmt.Sprint(l["secret_id"]), "user_id": fmt.Sprint(l["user_id"])}})
	}
}

// Expected is the row count each target table should hold once the mapped
// rows are in: the bundle's count, plus the comments the mapping adds.
func (r *Result) Expected() map[string]int {
	out := map[string]int{}
	for k, v := range r.Rows {
		out[k] = len(v)
	}
	return out
}
