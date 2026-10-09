// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/mapping"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
)

// Lister is the part of the Kratos admin API the inventory reads.
type Lister interface {
	List(ctx context.Context, withPassword bool) ([]kratos.Identity, error)
}

// Token is a personal token by id, never its hash.
type Token struct {
	ID      string `json:"id"`
	UserID  string `json:"user_id"`
	Active  bool   `json:"active"`
	Client  string `json:"client,omitempty"`
	Created string `json:"created_at,omitempty"`
}

// InventoryReport is a source's size and shape: counts and names only. It
// needs no key, opens no value and writes no bundle.
type InventoryReport struct {
	At                string         `json:"at"`
	Profile           string         `json:"source_profile"`
	Tables            map[string]int `json:"tables"`
	ByFolder          map[string]int `json:"secrets_by_folder"`
	ByType            map[string]int `json:"secrets_by_type"`
	UnusedTypes       []string       `json:"unused_types"`
	UsersByRole       map[string]int `json:"users_by_role"`
	PersonalTokens    []Token        `json:"personal_tokens"`
	RotationSchedules int            `json:"rotation_schedules"`
	HeartbeatSchedule int            `json:"heartbeat_schedules"`
	KratosIdentities  int            `json:"kratos_identities"`
}

// Inventory reads the source's counts in read-only snapshots.
func Inventory(ctx context.Context, dsn map[schema.Service]string, kr Lister, lg log.Logger) (*InventoryReport, error) {
	inv := &InventoryReport{At: time.Now().UTC().Format(time.RFC3339), Profile: schema.SourceProfile.Name, Tables: map[string]int{}, UsersByRole: map[string]int{}}
	rows := map[string][]mapping.Row{}
	for _, s := range schema.Services {
		db, err := postgres.New(ctx, dsn[s])
		if err != nil {
			return nil, fmt.Errorf("connect to the %s database: %w", s, err)
		}
		err = db.RunInTx(ctx, func(tx postgres.Tx) error {
			if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil {
				return err
			}
			if err := checkVersion(ctx, tx, s); err != nil {
				return err
			}
			for _, t := range schema.Of(s) {
				var n int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+t.Name).Scan(&n); err != nil { // #nosec G202 -- names come from the fixed table list
					return fmt.Errorf("count %s: %w", t.Stream(), err)
				}
				inv.Tables[t.Stream()] = n
			}
			return inventoryRows(ctx, tx, s, inv, rows)
		})
		db.Close()
		if err != nil {
			return nil, err
		}
	}
	rv, err := mapping.Review(&mapping.Result{Rows: rows})
	if err != nil {
		return nil, err
	}
	inv.ByFolder, inv.ByType, inv.UnusedTypes = rv.ByFolder, rv.ByType, rv.UnusedTypes
	inv.RotationSchedules, inv.HeartbeatSchedule = inv.Tables["vault.rotation_schedule"], inv.Tables["vault.heartbeat_schedule"]
	if kr != nil {
		ids, err := kr.List(ctx, false)
		if err != nil {
			return nil, fmt.Errorf("source Kratos: %w", err)
		}
		inv.KratosIdentities = len(ids)
	}
	lg.Info("inventory read", log.F("secrets", inv.Tables["vault.secrets"]), log.F("users", inv.Tables["identity.users"]))
	return inv, nil
}

// inventoryRows reads the name-only columns the per-folder and per-type
// counts need: never a sealed record, a hash or a token.
func inventoryRows(ctx context.Context, q postgres.Querier, s schema.Service, inv *InventoryReport, rows map[string][]mapping.Row) error {
	read := func(stream, sql string) error {
		rs, err := q.Query(ctx, sql)
		if err != nil {
			return fmt.Errorf("read %s: %w", stream, err)
		}
		defer rs.Close()
		for rs.Next() {
			var raw string
			if err := rs.Scan(&raw); err != nil {
				return err
			}
			var row mapping.Row
			if err := bundle.Decode([]byte(raw), &row); err != nil {
				return err
			}
			rows[stream] = append(rows[stream], row)
		}
		return rs.Err()
	}
	switch s {
	case schema.Identity:
		if err := read("identity.users", "SELECT json_build_object('id', id, 'email', email, 'roles', roles)::text FROM public.users ORDER BY id"); err != nil {
			return err
		}
		for _, u := range rows["identity.users"] {
			roles, _ := u["roles"].([]any)
			if len(roles) == 0 {
				inv.UsersByRole["user"]++
			}
			for _, r := range roles {
				inv.UsersByRole[fmt.Sprint(r)]++
			}
		}
		rs, err := q.Query(ctx, "SELECT id, user_id, revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()), client_name, created_at FROM public.user_tokens ORDER BY id")
		if err != nil {
			return fmt.Errorf("read identity.user_tokens: %w", err)
		}
		defer rs.Close()
		for rs.Next() {
			var t Token
			var at time.Time
			if err := rs.Scan(&t.ID, &t.UserID, &t.Active, &t.Client, &at); err != nil {
				return err
			}
			t.Created = at.UTC().Format(time.RFC3339)
			inv.PersonalTokens = append(inv.PersonalTokens, t)
		}
		return rs.Err()
	case schema.Vault:
		for stream, sql := range map[string]string{
			"vault.folders":      "SELECT json_build_object('id', id, 'data', json_build_object('name', data->'name', 'parentId', data->'parentId', 'scope', data->'scope', 'ownerUserId', data->'ownerUserId'))::text FROM public.folders ORDER BY id",
			"vault.secrets":      "SELECT json_build_object('id', id, 'data', json_build_object('name', data->'name', 'folderId', data->'folderId', 'typeId', data->'typeId', 'retired', data->'retired'))::text FROM public.secrets ORDER BY id",
			"vault.secret_types": "SELECT json_build_object('id', id, 'data', json_build_object('name', data->'name'))::text FROM public.secret_types ORDER BY id",
		} {
			if err := read(stream, sql); err != nil {
				return err
			}
		}
	}
	return nil
}
