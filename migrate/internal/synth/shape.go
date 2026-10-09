// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package synth

import (
	"context"
	"fmt"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-release/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/envelope"
	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/schema"
)

// Shape lays the vault out to a given plan instead of the default tree: a
// dry run in the shape of a real inventory (the same counts of folders,
// types, secrets, targets and connections) with invented names and values.
type Shape struct {
	Folders []ShapeFolder `json:"folders"`
	Types   []ShapeType   `json:"types"`
	Secrets []ShapeSecret `json:"secrets"`
	// SSHTargets and LDAPTargets are made in that order; a secret's Target
	// indexes the list.
	SSHTargets  int `json:"ssh_targets"`
	LDAPTargets int `json:"ldap_targets"`
}

// ShapeFolder is one folder by path; PersonalOwner (a user index, 1-based)
// makes it that user's personal folder.
type ShapeFolder struct {
	Path          []string `json:"path"`
	PersonalOwner int      `json:"personal_owner,omitempty"`
}

// ShapeType is one secret type with the fields of a template: password,
// web, ssh-key, ad, unix-ssh, api-token, note, cert, windows-local, oauth,
// legacy-domain or custom.
type ShapeType struct {
	Name     string `json:"name"`
	Template string `json:"template"`
}

// ShapeSecret is one secret: its folder and type by index, its name, and a
// target index (0 for none, else 1-based).
type ShapeSecret struct {
	Folder int    `json:"folder"`
	Type   int    `json:"type"`
	Name   string `json:"name"`
	Target int    `json:"target,omitempty"`
}

func shapeType(i int, st ShapeType) (*vaultv1.SecretType, error) {
	sys := vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM
	text, pw, sens, multi := vaultv1.FieldKind_FIELD_KIND_TEXT, vaultv1.FieldKind_FIELD_KIND_PASSWORD, vaultv1.FieldKind_FIELD_KIND_SENSITIVE, vaultv1.FieldKind_FIELD_KIND_MULTILINE
	t := &vaultv1.SecretType{Id: fmt.Sprintf("type-shape-%02d", i+1), Name: st.Name, Origin: sys}
	f := func(key, label string, kind vaultv1.FieldKind) *vaultv1.SecretFieldDef {
		return &vaultv1.SecretFieldDef{Key: key, Label: label, Kind: kind, Sensitive: kind == sens}
	}
	switch st.Template {
	case "password":
		t.Rotation = true
		t.Fields = []*vaultv1.SecretFieldDef{f("username", "Username", text), f("password", "Password", pw), f("notes", "Notes", multi)}
	case "web":
		t.Fields = []*vaultv1.SecretFieldDef{f("url", "URL", text), f("username", "Username", text), f("password", "Password", pw)}
	case "ssh-key":
		t.Fields = []*vaultv1.SecretFieldDef{f("username", "Username", text), f("private_key", "Private key", sens), f("passphrase", "Passphrase", pw)}
	case "ad":
		t.Rotation, t.Heartbeat, t.Checkout = true, true, true
		t.Fields = []*vaultv1.SecretFieldDef{f("domain", "Domain", text), f("username", "Username", text), f("password", "Password", pw)}
	case "unix-ssh":
		t.Rotation, t.Heartbeat = true, true
		t.Fields = []*vaultv1.SecretFieldDef{f("username", "Username", text), f("password", "Password", pw)}
	case "api-token":
		t.Fields = []*vaultv1.SecretFieldDef{f("token", "Token", sens), f("url", "URL", text)}
	case "note":
		t.Fields = []*vaultv1.SecretFieldDef{f("note", "Note", sens)}
	case "cert":
		t.Fields = []*vaultv1.SecretFieldDef{f("certificate", "Certificate", multi), f("private_key", "Private key", sens), f("passphrase", "Passphrase", pw)}
	case "windows-local":
		t.Rotation = true
		t.Fields = []*vaultv1.SecretFieldDef{f("hostname", "Host", text), f("username", "Username", text), f("password", "Password", pw)}
	case "oauth":
		t.Fields = []*vaultv1.SecretFieldDef{f("client_id", "Client ID", text), f("client_secret", "Client secret", sens), f("url", "URL", text)}
	case "legacy-domain":
		t.Fields = []*vaultv1.SecretFieldDef{f("domain", "Domain", text), f("user", "User", text), f("pass", "Password", pw)}
	case "custom":
		t.Origin = vaultv1.TypeOrigin_TYPE_ORIGIN_CUSTOM
		t.Fields = []*vaultv1.SecretFieldDef{f("key", "Key", pw), f("notes", "Notes", multi)}
	default:
		return nil, fmt.Errorf("shape: type %q has unknown template %q", st.Name, st.Template)
	}
	return t, nil
}

// vaultShaped seeds the vault to the shape.
func (g *gen) vaultShaped(ctx context.Context, db *postgres.DB, ring []envelope.KeyringRow) error {
	q := db.Querier()
	sh := g.opts.Shape
	for i, r := range ring {
		row := map[string]any{"ref": r.Ref, "wrapped_key": r.WrappedKey, "root_ref": r.RootRef, "active": r.Active, "created_at": g.ago(400 - i*300)}
		if !r.Active {
			row["retired_at"] = g.ago(60)
		}
		if err := g.insert(ctx, q, schema.Vault, "kek_keyring", row); err != nil {
			return err
		}
	}
	types := make([]*vaultv1.SecretType, len(sh.Types))
	for i, st := range sh.Types {
		t, err := shapeType(i, st)
		if err != nil {
			return err
		}
		types[i] = t
		raw, err := pj(t)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "secret_types", map[string]any{"id": t.GetId(), "data": raw}); err != nil {
			return err
		}
	}
	set, err := pj(&vaultv1.SecuritySettings{RequireMfaForSensitiveCheckout: true, SessionTtlSeconds: 1800, KekRotationDays: 90})
	if err != nil {
		return err
	}
	if err := g.insert(ctx, q, schema.Vault, "security_settings", map[string]any{"id": 1, "data": set}); err != nil {
		return err
	}

	ids := map[string]string{}
	folderIDs := make([]string, len(sh.Folders))
	for i, f := range sh.Folders {
		id := fmt.Sprintf("folder-shape-%02d", i+1)
		folderIDs[i] = id
		parent := ""
		if len(f.Path) > 1 {
			parent = ids[fmt.Sprint(f.Path[:len(f.Path)-1])]
			if parent == "" {
				return fmt.Errorf("shape: folder %v comes before its parent", f.Path)
			}
		}
		ids[fmt.Sprint(f.Path)] = id
		fo := &vaultv1.Folder{Id: id, Name: f.Path[len(f.Path)-1], ParentId: parent, Order: int32(i)} // #nosec G115 -- a small folder list
		if f.PersonalOwner > 0 {
			fo.Scope, fo.OwnerUserId = vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, g.user(f.PersonalOwner-1).id
		} else {
			fo.Owners = []string{g.user(0).id}
		}
		raw, err := pj(fo)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "folders", map[string]any{"id": id, "data": raw}); err != nil {
			return err
		}
		if f.PersonalOwner == 0 && i%3 == 0 {
			r := &vaultv1.FolderAccessRule{Id: fmt.Sprintf("frule-shape-%02d", i+1), FolderId: id, SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectId: "grp-01", Role: vaultv1.FolderRole(1 + i%5)}
			raw, err := pj(r)
			if err != nil {
				return err
			}
			if err := g.insert(ctx, q, schema.Vault, "folder_rules", map[string]any{"id": r.GetId(), "data": raw}); err != nil {
				return err
			}
		}
	}

	conns := []*vaultv1.Connection{
		{Id: "conn-ssh-default", Name: "Default SSH", Protocol: "ssh", Port: 22},
		{Id: "conn-winrm-default", Name: "Default WinRM", Protocol: "winrm", Port: 5986, UseTls: true},
		{Id: "conn-ldaps", Name: "Directory (LDAPS)", Protocol: "ldap", Port: 636, UseTls: true},
	}
	for _, c := range conns {
		raw, err := pj(c)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "connections", map[string]any{"id": c.GetId(), "data": raw}); err != nil {
			return err
		}
	}
	var targets []string
	for i := 0; i < sh.SSHTargets+sh.LDAPTargets; i++ {
		t := &vaultv1.Target{Id: fmt.Sprintf("tgt-shape-%02d", i+1)}
		if i < sh.SSHTargets {
			t.Name, t.Hostname, t.ConnectionId, t.Kind = fmt.Sprintf("host-%02d", i+1), fmt.Sprintf("host%02d.example.org", i+1), "conn-ssh-default", "ssh"
		} else {
			n := i - sh.SSHTargets + 1
			t.Name, t.Hostname, t.ConnectionId, t.Kind = fmt.Sprintf("directory-%d", n), fmt.Sprintf("dc%02d.corp.example.org", n), "conn-ldaps", "ad"
			t.Domain, t.Realm = "CORP", "CORP.EXAMPLE.ORG"
		}
		raw, err := pj(t)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "targets", map[string]any{"id": t.GetId(), "data": raw}); err != nil {
			return err
		}
		targets = append(targets, t.Id)
	}

	pos := map[int]int32{}
	for i, s := range sh.Secrets {
		if s.Folder < 0 || s.Folder >= len(folderIDs) || s.Type < 0 || s.Type >= len(types) || s.Target < 0 || s.Target > len(targets) {
			return fmt.Errorf("shape: secret %d points outside the folder, type or target lists", i)
		}
		id := fmt.Sprintf("sec-%04d", i+1)
		t := types[s.Type]
		pos[s.Folder]++
		sec := &vaultv1.Secret{Id: id, Name: s.Name, TypeId: t.GetId(), FolderId: folderIDs[s.Folder], Position: pos[s.Folder]}
		if s.Target > 0 {
			sec.TargetId = targets[s.Target-1]
		}
		if t.GetRotation() {
			sec.RotationIntervalDays = 30
		}
		versions := 1 + i%3
		var cur map[string]string
		for v := 1; v <= versions; v++ {
			fields := g.fieldsFor(t, i)
			ref := "kek-v2"
			if v < versions {
				ref = "kek-v1"
			}
			raw, err := g.seal(ref, fields)
			if err != nil {
				return err
			}
			row := map[string]any{"secret_id": id, "version_no": v, "record": raw, "active": v == versions, "created_at": g.ago(400 - v*50), "created_by": g.user(i + v).id}
			if err := g.insert(ctx, q, schema.Vault, "secret_versions", row); err != nil {
				return err
			}
			cur = fields
		}
		rec, err := g.seal("kek-v2", cur)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "secret_records", map[string]any{"secret_id": id, "record": rec}); err != nil {
			return err
		}
		raw, err := pj(sec)
		if err != nil {
			return err
		}
		if err := g.insert(ctx, q, schema.Vault, "secrets", map[string]any{"id": id, "data": raw}); err != nil {
			return err
		}
		if t.GetRotation() {
			row := map[string]any{"secret_id": id, "next_rotation_at": g.now.Add(time.Duration(1+i%30) * 24 * time.Hour), "interval_days": 30, "state": 1}
			if err := g.insert(ctx, q, schema.Vault, "rotation_schedule", row); err != nil {
				return err
			}
		}
	}
	return nil
}
