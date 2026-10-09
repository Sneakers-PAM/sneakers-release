// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package mapping

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The mapping file (docs/migrate.md#the-mapping-file) re-maps folders,
// secret names and secret types on the way in, and drops what the owner
// decided to leave behind. It names things only, never a value.
const (
	MappingFormat  = "sneakers-migrate-mapping"
	MappingVersion = 1
	UnlistedKeep   = "keep"
	UnlistedRefuse = "refuse"
)

// ErrMapping marks a mapping file that is invalid or doesn't fit the bundle.
var ErrMapping = errors.New("mapping")

func mappingErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMapping, fmt.Sprintf(format, a...))
}

// Path is a folder path from the root, one name per element. In the file it
// is a string split on "/" or, for a name that holds a "/", a list of names.
type Path []string

// UnmarshalJSON accepts "a/b" or ["a", "b"].
func (p *Path) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		*p = nil
		for _, part := range strings.Split(s, "/") {
			if part = strings.TrimSpace(part); part != "" {
				*p = append(*p, part)
			}
		}
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return errors.New("a folder path is a string or a list of names")
	}
	*p = Path(list)
	return nil
}

func (p Path) String() string { return strings.Join(p, " / ") }

func (p Path) key() string { return strings.Join(p, "\x00") }

// Ref names a secret or a folder by where it is. Owner (an email) picks one
// of several personal folders that share a path.
type Ref struct {
	Folder Path   `json:"folder,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
}

// FolderRule moves or renames one folder (keeping its id and access rules),
// or drops it once nothing is left in it.
type FolderRule struct {
	From  Path   `json:"from"`
	Owner string `json:"owner,omitempty"`
	To    Path   `json:"to,omitempty"`
	Drop  bool   `json:"drop,omitempty"`
}

// TypeRule says how the fields of a secret of type From land in type To:
// Fields maps a source field key to a target one (unlisted keys keep their
// key), and DropFields may be lost. Anything else that would be lost refuses.
type TypeRule struct {
	From       string            `json:"from"`
	To         string            `json:"to"`
	Fields     map[string]string `json:"fields,omitempty"`
	DropFields []string          `json:"drop_fields,omitempty"`
}

// SecretRule re-maps one secret, matched by ID or by From, or drops it.
type SecretRule struct {
	ID   string `json:"id,omitempty"`
	From Ref    `json:"from"`
	To   *Ref   `json:"to,omitempty"`
	Drop bool   `json:"drop,omitempty"`
}

// Plan is a parsed mapping file.
type Plan struct {
	Format   string `json:"format"`
	Version  int    `json:"version"`
	Unlisted string `json:"unlisted"`
	// BundleID keys the file to the one bundle it was written for; an import
	// outside rehearsal mode needs it to match.
	BundleID string       `json:"bundle_id,omitempty"`
	Folders  []FolderRule `json:"folders,omitempty"`
	Types    []TypeRule   `json:"types,omitempty"`
	Secrets  []SecretRule `json:"secrets,omitempty"`
	// SHA256 is the file's hash, recorded on the audit chain.
	SHA256 string `json:"-"`
}

// ParsePlan reads a mapping file strictly: unknown keys are refused.
func ParsePlan(raw []byte) (*Plan, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var p Plan
	if err := d.Decode(&p); err != nil {
		return nil, mappingErr("the file does not parse: %v", err)
	}
	if p.Format != MappingFormat || p.Version != MappingVersion {
		return nil, mappingErr("format %q version %d; this tool reads %q version %d", p.Format, p.Version, MappingFormat, MappingVersion)
	}
	if p.Unlisted != UnlistedKeep && p.Unlisted != UnlistedRefuse {
		return nil, mappingErr("unlisted is %q; say %q or %q for the secrets the file doesn't name", p.Unlisted, UnlistedKeep, UnlistedRefuse)
	}
	for i, f := range p.Folders {
		if len(f.From) == 0 || (f.Drop == (len(f.To) > 0)) {
			return nil, mappingErr("folders[%d]: give from, and either to or drop", i)
		}
	}
	for i, t := range p.Types {
		if t.From == "" || t.To == "" {
			return nil, mappingErr("types[%d]: give from and to", i)
		}
	}
	for i, s := range p.Secrets {
		if s.ID == "" && s.From.Name == "" {
			return nil, mappingErr("secrets[%d]: give id or from.name", i)
		}
		if s.Drop == (s.To != nil) {
			return nil, mappingErr("secrets[%d]: give either to or drop", i)
		}
	}
	sum := sha256.Sum256(raw)
	p.SHA256 = hex.EncodeToString(sum[:])
	return &p, nil
}

// RemapStats counts what a plan changed.
type RemapStats struct {
	MappingSHA256  string `json:"mapping_sha256"`
	FoldersMoved   int    `json:"folders_moved"`
	FoldersCreated int    `json:"folders_created"`
	FoldersDropped int    `json:"folders_dropped"`
	SecretsMoved   int    `json:"secrets_moved"`
	SecretsRenamed int    `json:"secrets_renamed"`
	SecretsRetyped int    `json:"secrets_retyped"`
	SecretsDropped int    `json:"secrets_dropped"`
	SecretsKept    int    `json:"secrets_unlisted_kept"`
	// Warnings are non-fatal findings, such as two secrets with one name in
	// one folder.
	Warnings []string `json:"warnings,omitempty"`
}

type folderNode struct {
	row      Row
	data     map[string]any
	id       string
	name     string
	parent   string
	owner    string
	personal bool
}

type secretNode struct {
	row  Row
	data map[string]any
	id   string
}

type remapper struct {
	r       *Result
	plan    *Plan
	stats   *RemapStats
	folders map[string]*folderNode
	order   []string // folder ids in bundle order
	secrets map[string]*secretNode
	sOrder  []string
	email   map[string]string // user id -> email
	types   map[string]map[string]any
	// original paths, for matching from
	origPath map[string]Path
	touched  map[string]bool // folders whose secrets changed
}

func dataOf(row Row) (map[string]any, error) {
	switch v := row["data"].(type) {
	case map[string]any:
		return v, nil
	case string:
		var m map[string]any
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil, err
		}
		row["data"] = m
		return m, nil
	}
	return nil, errors.New("data is not a JSON object")
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// applyPlan re-maps the rows. Rules match the bundle's own folder tree and
// names; folder rules run first, in order, then the secret rules.
func (r *Result) applyPlan(p *Plan) error {
	x := &remapper{r: r, plan: p, stats: &RemapStats{MappingSHA256: p.SHA256}, folders: map[string]*folderNode{}, secrets: map[string]*secretNode{},
		email: map[string]string{}, types: map[string]map[string]any{}, origPath: map[string]Path{}, touched: map[string]bool{}}
	if err := x.load(); err != nil {
		return err
	}
	for id := range x.folders {
		x.origPath[id] = x.path(id)
	}
	if err := x.folderRules(); err != nil {
		return err
	}
	if err := x.secretRules(); err != nil {
		return err
	}
	if err := x.dropFolders(); err != nil {
		return err
	}
	x.positions()
	x.warnDuplicates()
	r.Remap = x.stats
	return nil
}

func (x *remapper) load() error {
	for _, u := range x.r.Rows["identity.users"] {
		x.email[fmt.Sprint(u["id"])] = strings.ToLower(fmt.Sprint(u["email"]))
	}
	for _, row := range x.r.Rows["vault.folders"] {
		d, err := dataOf(row)
		if err != nil {
			return fmt.Errorf("vault.folders: %w", err)
		}
		n := &folderNode{row: row, data: d, id: fmt.Sprint(row["id"]), name: str(d, "name"), parent: str(d, "parentId"), owner: str(d, "ownerUserId"), personal: str(d, "scope") == "FOLDER_SCOPE_PERSONAL"}
		x.folders[n.id] = n
		x.order = append(x.order, n.id)
	}
	for _, row := range x.r.Rows["vault.secrets"] {
		d, err := dataOf(row)
		if err != nil {
			return fmt.Errorf("vault.secrets: %w", err)
		}
		n := &secretNode{row: row, data: d, id: fmt.Sprint(row["id"])}
		x.secrets[n.id] = n
		x.sOrder = append(x.sOrder, n.id)
	}
	for _, row := range x.r.Rows["vault.secret_types"] {
		d, err := dataOf(row)
		if err != nil {
			return fmt.Errorf("vault.secret_types: %w", err)
		}
		x.types[fmt.Sprint(row["id"])] = d
	}
	return nil
}

// path is a folder's current path; a cycle or a missing parent ends it.
func (x *remapper) path(id string) Path {
	var out Path
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		seen[id] = true
		f, ok := x.folders[id]
		if !ok {
			break
		}
		out = append(Path{f.name}, out...)
		id = f.parent
	}
	return out
}

// ownerOf is the email of the nearest owner up a personal folder's tree.
func (x *remapper) ownerOf(id string) string {
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		seen[id] = true
		f, ok := x.folders[id]
		if !ok {
			return ""
		}
		if f.owner != "" {
			return x.email[f.owner]
		}
		id = f.parent
	}
	return ""
}

// find returns the folders at path p (on the original tree, or the current
// one), narrowed to owner when given.
func (x *remapper) find(p Path, owner string, original bool) []string {
	var out []string
	for _, id := range x.order {
		f := x.folders[id]
		if f == nil {
			continue
		}
		cur := x.origPath[id]
		if !original {
			cur = x.path(id)
		}
		if cur.key() != p.key() {
			continue
		}
		if owner != "" && x.ownerOf(id) != strings.ToLower(owner) {
			continue
		}
		out = append(out, id)
	}
	return out
}

func (x *remapper) one(p Path, owner string, original bool, what string) (string, error) {
	ids := x.find(p, owner, original)
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return "", mappingErr("%s: no folder %q%s in the bundle", what, p.String(), ownerNote(owner))
	}
	return "", mappingErr("%s: %d folders are at %q%s; name the owner", what, len(ids), p.String(), ownerNote(owner))
}

func ownerNote(owner string) string {
	if owner == "" {
		return ""
	}
	return " (owner " + owner + ")"
}

// ensure returns the folder at p on the current tree, creating the missing
// shared folders on the way. A created folder's id is derived from its path,
// so import and verify make the same one.
func (x *remapper) ensure(p Path, owner, what string) (string, error) {
	if len(p) == 0 {
		return "", nil
	}
	ids := x.find(p, owner, false)
	switch {
	case len(ids) == 1:
		return ids[0], nil
	case len(ids) > 1:
		return "", mappingErr("%s: %d folders are at %q%s; name the owner", what, len(ids), p.String(), ownerNote(owner))
	case owner != "":
		return "", mappingErr("%s: no personal folder %q%s to move into", what, p.String(), ownerNote(owner))
	}
	parent, err := x.ensure(p[:len(p)-1], "", what)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(p.key()))
	id := "folder-mig-" + hex.EncodeToString(sum[:8])
	d := map[string]any{"id": id, "name": p[len(p)-1]}
	if parent != "" {
		d["parentId"] = parent
	}
	row := Row{"id": id, "data": d}
	x.r.Rows["vault.folders"] = append(x.r.Rows["vault.folders"], row)
	x.folders[id] = &folderNode{row: row, data: d, id: id, name: p[len(p)-1], parent: parent}
	x.order = append(x.order, id)
	x.origPath[id] = nil
	x.stats.FoldersCreated++
	return id, nil
}

func (x *remapper) inside(id, ancestor string) bool {
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		if id == ancestor {
			return true
		}
		seen[id] = true
		f, ok := x.folders[id]
		if !ok {
			return false
		}
		id = f.parent
	}
	return false
}

func (x *remapper) folderRules() error {
	ids := make([]string, len(x.plan.Folders))
	for i, fr := range x.plan.Folders {
		id, err := x.one(fr.From, fr.Owner, true, fmt.Sprintf("folders[%d]", i))
		if err != nil {
			return err
		}
		ids[i] = id
	}
	for i, fr := range x.plan.Folders {
		if fr.Drop {
			continue
		}
		f := x.folders[ids[i]]
		what := fmt.Sprintf("folders[%d]", i)
		parent, err := x.ensure(fr.To[:len(fr.To)-1], "", what)
		if err != nil {
			return err
		}
		if parent != "" && x.inside(parent, f.id) {
			return mappingErr("%s: %q can't move inside itself", what, fr.From.String())
		}
		if f.personal && parent != "" && !x.folders[parent].personal {
			return mappingErr("%s: personal folder %q can't move into a shared folder", what, fr.From.String())
		}
		f.name, f.parent = fr.To[len(fr.To)-1], parent
		f.data["name"] = f.name
		if parent == "" {
			delete(f.data, "parentId")
		} else {
			f.data["parentId"] = parent
		}
		x.stats.FoldersMoved++
	}
	return nil
}

type typeKey struct{ from, to string }

func (x *remapper) typeByName(name, what string) (string, error) {
	var ids []string
	for id, d := range x.types {
		if str(d, "name") == name {
			ids = append(ids, id)
		}
	}
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return "", mappingErr("%s: no secret type %q in the bundle", what, name)
	}
	return "", mappingErr("%s: %d secret types are called %q", what, len(ids), name)
}

func (x *remapper) secretRules() error {
	typeRules := map[typeKey]TypeRule{}
	for i, tr := range x.plan.Types {
		from, err := x.typeByName(tr.From, fmt.Sprintf("types[%d]", i))
		if err != nil {
			return err
		}
		to, err := x.typeByName(tr.To, fmt.Sprintf("types[%d]", i))
		if err != nil {
			return err
		}
		typeRules[typeKey{from, to}] = tr
	}
	claimed := map[string]int{}
	drop := map[string]bool{}
	for i, sr := range x.plan.Secrets {
		what := fmt.Sprintf("secrets[%d]", i)
		id, err := x.matchSecret(sr, what)
		if err != nil {
			return err
		}
		if j, dup := claimed[id]; dup {
			return mappingErr("%s: secret %s is already re-mapped by secrets[%d]", what, id, j)
		}
		claimed[id] = i
		s := x.secrets[id]
		if sr.Drop {
			drop[id] = true
			x.touched[str(s.data, "folderId")] = true
			continue
		}
		if err := x.remapSecret(s, *sr.To, typeRules, what); err != nil {
			return err
		}
	}
	var unlisted []string
	for _, id := range x.sOrder {
		if _, ok := claimed[id]; !ok {
			unlisted = append(unlisted, id)
		}
	}
	if len(unlisted) > 0 && x.plan.Unlisted == UnlistedRefuse {
		shown := unlisted
		if len(shown) > 10 {
			shown = shown[:10]
		}
		return mappingErr("%d secrets are not in the mapping file and unlisted is %q: %s", len(unlisted), UnlistedRefuse, strings.Join(shown, ", "))
	}
	x.stats.SecretsKept = len(unlisted)
	return x.dropSecrets(drop)
}

func (x *remapper) matchSecret(sr SecretRule, what string) (string, error) {
	match := func(s *secretNode) bool {
		f := sr.From
		if f.Name != "" && str(s.data, "name") != f.Name {
			return false
		}
		if f.Type != "" && str(x.types[str(s.data, "typeId")], "name") != f.Type {
			return false
		}
		folder := str(s.data, "folderId")
		if len(f.Folder) > 0 && x.origPath[folder].key() != f.Folder.key() {
			return false
		}
		if f.Owner != "" && x.ownerOf(folder) != strings.ToLower(f.Owner) {
			return false
		}
		return true
	}
	if sr.ID != "" {
		s, ok := x.secrets[sr.ID]
		if !ok {
			return "", mappingErr("%s: no secret %s in the bundle", what, sr.ID)
		}
		if !match(s) {
			return "", mappingErr("%s: secret %s is not %q in %q as the file says", what, sr.ID, sr.From.Name, sr.From.Folder.String())
		}
		return sr.ID, nil
	}
	var ids []string
	for _, id := range x.sOrder {
		if match(x.secrets[id]) {
			ids = append(ids, id)
		}
	}
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return "", mappingErr("%s: no secret %q (type %q) in folder %q%s", what, sr.From.Name, sr.From.Type, sr.From.Folder.String(), ownerNote(sr.From.Owner))
	}
	return "", mappingErr("%s: %d secrets match %q in folder %q; give the id, type or owner", what, len(ids), sr.From.Name, sr.From.Folder.String())
}

func (x *remapper) remapSecret(s *secretNode, to Ref, typeRules map[typeKey]TypeRule, what string) error {
	oldFolder := str(s.data, "folderId")
	if len(to.Folder) > 0 {
		dest, err := x.ensure(to.Folder, to.Owner, what)
		if err != nil {
			return err
		}
		if dest != oldFolder {
			s.data["folderId"] = dest
			x.touched[oldFolder], x.touched[dest] = true, true
			x.stats.SecretsMoved++
		}
	}
	if to.Name != "" && to.Name != str(s.data, "name") {
		s.data["name"] = to.Name
		x.stats.SecretsRenamed++
	}
	if to.Type == "" {
		return nil
	}
	from := str(s.data, "typeId")
	dest, err := x.typeByName(to.Type, what)
	if err != nil {
		return err
	}
	if dest == from {
		return nil
	}
	rule, ok := typeRules[typeKey{from, dest}]
	if !ok {
		rule = TypeRule{From: str(x.types[from], "name"), To: to.Type}
	}
	if err := x.retype(s.id, dest, rule, what); err != nil {
		return err
	}
	s.data["typeId"] = dest
	x.schedules(s, x.types[dest])
	x.stats.SecretsRetyped++
	return nil
}

func typeFields(t map[string]any) map[string]bool {
	out := map[string]bool{}
	fs, _ := t["fields"].([]any)
	for _, f := range fs {
		if m, ok := f.(map[string]any); ok {
			out[str(m, "key")] = true
		}
	}
	return out
}

// retype moves every field of the secret's current value and versions into
// the target type's keys, and refuses to lose a non-empty one the rule
// doesn't let go.
func (x *remapper) retype(id, dest string, rule TypeRule, what string) error {
	keys := typeFields(x.types[dest])
	dropOK := map[string]bool{}
	for _, f := range rule.DropFields {
		dropOK[f] = true
	}
	for _, stream := range []string{"vault.secret_records", "vault.secret_versions"} {
		for _, row := range x.r.Rows[stream] {
			if fmt.Sprint(row["secret_id"]) != id {
				continue
			}
			fields, _ := row["fields"].(map[string]any)
			out := map[string]any{}
			for k, v := range fields {
				destKey, mapped := rule.Fields[k]
				if !mapped {
					destKey = k
				}
				empty := fmt.Sprint(v) == ""
				switch {
				case dropOK[k] && !mapped:
					continue
				case !keys[destKey] && empty:
					continue
				case !keys[destKey]:
					return mappingErr("%s: secret %s field %q has no place in type %q; map it under types or list it in drop_fields", what, id, k, rule.To)
				}
				if _, clash := out[destKey]; clash {
					return mappingErr("%s: secret %s: two fields land on %q in type %q", what, id, destKey, rule.To)
				}
				out[destKey] = v
			}
			row["fields"] = out
		}
	}
	return nil
}

// schedules drops a rotation or heartbeat schedule the new type can't run.
func (x *remapper) schedules(s *secretNode, t map[string]any) {
	rot, _ := t["rotation"].(bool)
	hb, _ := t["heartbeat"].(bool)
	if !rot {
		x.r.Rows["vault.rotation_schedule"] = without(x.r.Rows["vault.rotation_schedule"], "secret_id", map[string]bool{s.id: true})
		delete(s.data, "rotationIntervalDays")
		delete(s.data, "nextRotationAt")
	}
	if !hb {
		x.r.Rows["vault.heartbeat_schedule"] = without(x.r.Rows["vault.heartbeat_schedule"], "secret_id", map[string]bool{s.id: true})
		delete(s.data, "heartbeatIntervalSeconds")
		delete(s.data, "nextHeartbeatAt")
	}
}

func without(rows []Row, col string, ids map[string]bool) []Row {
	out := rows[:0]
	for _, r := range rows {
		if !ids[fmt.Sprint(r[col])] {
			out = append(out, r)
		}
	}
	return out
}

// dropSecrets removes the dropped secrets and every row that hangs off them.
func (x *remapper) dropSecrets(drop map[string]bool) error {
	if len(drop) == 0 {
		return nil
	}
	for _, c := range x.r.Rows["vault.connections"] {
		d, err := dataOf(c)
		if err != nil {
			return fmt.Errorf("vault.connections: %w", err)
		}
		if id := str(d, "privilegedSecretId"); drop[id] {
			return mappingErr("secret %s is dropped, but connection %v uses it as its privileged account", id, c["id"])
		}
	}
	rows := x.r.Rows
	rows["vault.secrets"] = without(rows["vault.secrets"], "id", drop)
	for _, s := range []string{"vault.secret_records", "vault.secret_versions", "vault.rotation_schedule", "vault.heartbeat_schedule", "vault.break_glass_events", "workflow.leases"} {
		rows[s] = without(rows[s], "secret_id", drop)
	}
	var uses []Row
	for _, u := range rows["vault.secret_uses"] {
		d, err := dataOf(u)
		if err != nil {
			return fmt.Errorf("vault.secret_uses: %w", err)
		}
		if !drop[str(d, "secretId")] {
			uses = append(uses, u)
		}
	}
	rows["vault.secret_uses"] = uses
	var grants []Row
	for _, g := range rows["vault.secret_use_grants"] {
		d, err := dataOf(g)
		if err != nil {
			return fmt.Errorf("vault.secret_use_grants: %w", err)
		}
		ids, _ := d["secretIds"].([]any)
		var keep []any
		for _, id := range ids {
			if !drop[fmt.Sprint(id)] {
				keep = append(keep, id)
			}
		}
		if len(ids) > 0 && len(keep) == 0 {
			continue
		}
		if len(keep) != len(ids) {
			d["secretIds"] = keep
		}
		grants = append(grants, g)
	}
	rows["vault.secret_use_grants"] = grants
	reqs := map[string]bool{}
	for _, a := range rows["workflow.approval_requests"] {
		if drop[fmt.Sprint(a["secret_id"])] {
			reqs[fmt.Sprint(a["id"])] = true
		}
	}
	rows["workflow.approval_requests"] = without(rows["workflow.approval_requests"], "id", reqs)
	rows["workflow.approval_comments"] = without(rows["workflow.approval_comments"], "request_id", reqs)
	events := x.r.Events[:0]
	for _, e := range x.r.Events {
		if !drop[e.Subject] && !drop[e.Attrs["secret_id"]] && !reqs[e.Subject] {
			events = append(events, e)
		}
	}
	x.r.Events = events
	ids := make([]string, 0, len(drop))
	for id := range drop {
		ids = append(ids, id)
		delete(x.secrets, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		x.r.Events = append(x.r.Events, Event{Action: "secret.dropped_by_migration", Subject: id})
	}
	keep := x.sOrder[:0]
	for _, id := range x.sOrder {
		if !drop[id] {
			keep = append(keep, id)
		}
	}
	x.sOrder = keep
	x.stats.SecretsDropped = len(drop)
	return nil
}

func (x *remapper) dropFolders() error {
	drop := map[string]bool{}
	for i, fr := range x.plan.Folders {
		if !fr.Drop {
			continue
		}
		id, err := x.one(fr.From, fr.Owner, true, fmt.Sprintf("folders[%d]", i))
		if err != nil {
			return err
		}
		for _, sid := range x.sOrder {
			if str(x.secrets[sid].data, "folderId") == id {
				return mappingErr("folders[%d]: %q still holds secret %s; move or drop it first", i, fr.From.String(), sid)
			}
		}
		for _, fid := range x.order {
			if f := x.folders[fid]; f != nil && f.parent == id && !drop[fid] {
				return mappingErr("folders[%d]: %q still holds folder %q; move or drop it first", i, fr.From.String(), f.name)
			}
		}
		drop[id] = true
	}
	if len(drop) == 0 {
		return nil
	}
	rows := x.r.Rows
	rows["vault.folders"] = without(rows["vault.folders"], "id", drop)
	for _, s := range []string{"vault.folder_rules", "vault.raci_rules"} {
		var keep []Row
		for _, r := range rows[s] {
			d, err := dataOf(r)
			if err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
			if !drop[str(d, "folderId")] {
				keep = append(keep, r)
			}
		}
		rows[s] = keep
	}
	for id := range drop {
		delete(x.folders, id)
	}
	x.stats.FoldersDropped = len(drop)
	return nil
}

// positions renumbers the active secrets of every folder that gained or lost
// one, keeping their order: 1-based and dense, as the vault keeps them.
func (x *remapper) positions() {
	by := map[string][]*secretNode{}
	for _, id := range x.sOrder {
		s := x.secrets[id]
		f := str(s.data, "folderId")
		if !x.touched[f] {
			continue
		}
		if retired, _ := s.data["retired"].(bool); retired {
			s.data["position"] = 0
			continue
		}
		by[f] = append(by[f], s)
	}
	for _, list := range by {
		sort.SliceStable(list, func(i, j int) bool {
			pi, pj := num(list[i].data["position"]), num(list[j].data["position"])
			if pi != pj {
				return pi < pj
			}
			return str(list[i].data, "name") < str(list[j].data, "name")
		})
		for i, s := range list {
			s.data["position"] = i + 1
		}
	}
}

func (x *remapper) warnDuplicates() {
	seen := map[string]int{}
	for _, id := range x.sOrder {
		s := x.secrets[id]
		seen[str(s.data, "folderId")+"\x00"+strings.ToLower(str(s.data, "name"))]++
	}
	var keys []string
	for k, n := range seen {
		if n > 1 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts := strings.SplitN(k, "\x00", 2)
		x.stats.Warnings = append(x.stats.Warnings, fmt.Sprintf("%d secrets share the name %q in folder %q", seen[k], parts[1], x.path(parts[0]).String()))
	}
}

// placeSecrets numbers the active secrets of every folder where one has no
// place yet (the earlier system kept none): 1-based and dense, by any place
// already held, then name (case-insensitive), then id, as the vault's own
// backfill does. A retired secret has no place.
func (r *Result) placeSecrets() error {
	x := &remapper{r: r, folders: map[string]*folderNode{}, secrets: map[string]*secretNode{}, email: map[string]string{}, types: map[string]map[string]any{}, touched: map[string]bool{}}
	if err := x.load(); err != nil {
		return err
	}
	for _, id := range x.sOrder {
		d := x.secrets[id].data
		retired, _ := d["retired"].(bool)
		if retired {
			delete(d, "position")
			continue
		}
		if num(d["position"]) == 0 {
			x.touched[str(d, "folderId")] = true
		}
	}
	by := map[string][]*secretNode{}
	for _, id := range x.sOrder {
		s := x.secrets[id]
		if retired, _ := s.data["retired"].(bool); !retired && x.touched[str(s.data, "folderId")] {
			by[str(s.data, "folderId")] = append(by[str(s.data, "folderId")], s)
		}
	}
	for _, list := range by {
		sort.SliceStable(list, func(i, j int) bool {
			pi, pj := num(list[i].data["position"]), num(list[j].data["position"])
			if (pi == 0) != (pj == 0) {
				return pi != 0
			}
			if pi != pj {
				return pi < pj
			}
			ni, nj := strings.ToLower(str(list[i].data, "name")), strings.ToLower(str(list[j].data, "name"))
			if ni != nj {
				return ni < nj
			}
			return list[i].id < list[j].id
		})
		for i, s := range list {
			s.data["position"] = i + 1
		}
	}
	return nil
}
