// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package mapping

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
)

// tsvColumns is the proposal sheet's layout: one row per secret, folders by
// their own name (not their path), and an action of carry or drop. An
// optional id column pins a row to one secret.
var tsvColumns = []string{"current_folder", "current_name", "current_type", "new_folder", "new_name", "new_type", "action"}

// PlanFromTSV turns a proposal sheet into a mapping file for this bundle:
// each row is resolved to exactly one secret and written with its id and
// full folder path. A folder named on its own resolves to the one shared
// folder of that name; "Personal" is the owner's personal folder (personal
// is the email of the account whose personal secrets the sheet lists). A
// new folder name is made under parent, and a folder whose secrets all move
// to one new name is renamed instead, so it keeps its access rules. Secrets
// the sheet doesn't list stay as they are. types carries the field mapping
// for each type change (the sheet has none); one missing is refused when the
// plan is applied, not guessed.
func PlanFromTSV(in io.Reader, r *Result, parent Path, personal string, types []TypeRule) (*Plan, []string, error) {
	cr := csv.NewReader(in)
	cr.Comma, cr.LazyQuotes, cr.FieldsPerRecord = '\t', true, -1
	recs, err := cr.ReadAll()
	if err != nil {
		return nil, nil, mappingErr("the sheet does not parse: %v", err)
	}
	if len(recs) == 0 {
		return nil, nil, mappingErr("the sheet has no header")
	}
	col := map[string]int{}
	for i, h := range recs[0] {
		col[strings.TrimSpace(h)] = i
	}
	for _, c := range tsvColumns {
		if _, ok := col[c]; !ok {
			return nil, nil, mappingErr("the sheet's header has no %q column (want %s)", c, strings.Join(tsvColumns, ", "))
		}
	}
	x := &remapper{r: r, folders: map[string]*folderNode{}, secrets: map[string]*secretNode{}, email: map[string]string{}, types: map[string]map[string]any{}, origPath: map[string]Path{}}
	if err := x.load(); err != nil {
		return nil, nil, err
	}
	for id := range x.folders {
		x.origPath[id] = x.path(id)
	}
	get := func(rec []string, c string) string {
		i, ok := col[c]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	type row struct {
		line                      int
		id                        string
		curFolder, newFolder      string
		newName, newType, curType string
		drop                      bool
	}
	var rows []row
	used := map[string]int{}
	for i, rec := range recs[1:] {
		line := i + 2
		w := row{line: line, curFolder: get(rec, "current_folder"), newFolder: get(rec, "new_folder"), newName: get(rec, "new_name"), newType: get(rec, "new_type"), curType: get(rec, "current_type")}
		switch get(rec, "action") {
		case "carry":
		case "drop":
			w.drop = true
		default:
			return nil, nil, mappingErr("line %d: action %q (carry or drop)", line, get(rec, "action"))
		}
		id, err := x.sheetSecret(get(rec, "id"), w.curFolder, get(rec, "current_name"), w.curType, personal)
		if err != nil {
			return nil, nil, mappingErr("line %d: %v", line, err)
		}
		if j, dup := used[id]; dup {
			return nil, nil, mappingErr("line %d: the same secret as line %d", line, j)
		}
		used[id], w.id = line, id
		rows = append(rows, w)
	}

	// A folder renamed: every one of its secrets moves to one name no folder has.
	moves := map[string]map[string]bool{} // current folder id -> new names
	count := map[string]int{}
	for _, w := range rows {
		f := str(x.secrets[w.id].data, "folderId")
		count[f]++
		if w.drop {
			continue
		}
		if moves[f] == nil {
			moves[f] = map[string]bool{}
		}
		moves[f][w.newFolder] = true
	}
	renamed := map[string]string{} // new name -> folder id
	var folderIDs []string
	for f := range moves {
		folderIDs = append(folderIDs, f)
	}
	sort.Strings(folderIDs)
	p := &Plan{Format: MappingFormat, Version: MappingVersion, Unlisted: UnlistedKeep, Types: types}
	var notes []string
	for _, f := range folderIDs {
		names := moves[f]
		if len(names) != 1 || x.folders[f] == nil || x.folders[f].personal || x.inSheetFolder(f) != count[f] {
			continue
		}
		var name string
		for n := range names {
			name = n
		}
		if name == "" || name == x.folders[f].name || len(x.byName(name)) > 0 || renamed[name] != "" {
			continue
		}
		renamed[name] = f
		to := append(append(Path{}, x.origPath[f][:len(x.origPath[f])-1]...), name)
		p.Folders = append(p.Folders, FolderRule{From: x.origPath[f], To: to})
		notes = append(notes, fmt.Sprintf("folder %q is renamed %q (all its secrets move there), keeping its access rules", x.origPath[f].String(), to.String()))
	}
	newPath := func(name string) Path {
		if f, ok := renamed[name]; ok {
			p := x.origPath[f]
			return append(append(Path{}, p[:len(p)-1]...), name)
		}
		if ids := x.byName(name); len(ids) == 1 {
			return x.origPath[ids[0]]
		}
		return append(append(Path{}, parent...), name)
	}
	for _, w := range rows {
		s := x.secrets[w.id]
		from := Ref{Folder: x.origPath[str(s.data, "folderId")], Owner: x.ownerOf(str(s.data, "folderId")), Name: str(s.data, "name"), Type: str(x.types[str(s.data, "typeId")], "name")}
		if w.drop {
			p.Secrets = append(p.Secrets, SecretRule{ID: w.id, From: from, Drop: true})
			continue
		}
		to := &Ref{Name: w.newName, Type: w.newType}
		switch {
		case w.newFolder == "Personal" && from.Owner != "":
			to.Folder, to.Owner = from.Folder, from.Owner
		case w.newFolder == "":
			return nil, nil, mappingErr("line %d: carry needs new_folder", w.line)
		default:
			to.Folder = newPath(w.newFolder)
		}
		p.Secrets = append(p.Secrets, SecretRule{ID: w.id, From: from, To: to})
	}
	return p, notes, nil
}

// byName is the shared folders with this name, or with this path.
func (x *remapper) byName(name string) []string {
	var out []string
	for _, id := range x.order {
		f := x.folders[id]
		if f == nil || f.personal {
			continue
		}
		if f.name == name || x.origPath[id].String() == name || strings.Join(x.origPath[id], "/") == name {
			out = append(out, id)
		}
	}
	return out
}

func (x *remapper) inSheetFolder(f string) int {
	n := 0
	for _, s := range x.secrets {
		if str(s.data, "folderId") == f {
			n++
		}
	}
	return n
}

// sheetSecret resolves one sheet row to a secret id.
func (x *remapper) sheetSecret(id, folder, name, typ, personal string) (string, error) {
	if id != "" {
		if _, ok := x.secrets[id]; !ok {
			return "", fmt.Errorf("no secret %s in the bundle", id)
		}
		return id, nil
	}
	var folders map[string]bool
	if folder == "Personal" {
		folders = map[string]bool{}
		for fid, f := range x.folders {
			if f.personal && (personal == "" || x.ownerOf(fid) == strings.ToLower(personal)) {
				folders[fid] = true
			}
		}
	} else {
		folders = map[string]bool{}
		for _, fid := range x.byName(folder) {
			folders[fid] = true
		}
	}
	var ids []string
	for _, sid := range x.sOrder {
		d := x.secrets[sid].data
		if folders[str(d, "folderId")] && str(d, "name") == name && (typ == "" || str(x.types[str(d, "typeId")], "name") == typ) {
			ids = append(ids, sid)
		}
	}
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return "", fmt.Errorf("no secret %q (type %q) in folder %q", name, typ, folder)
	}
	return "", fmt.Errorf("%d secrets are %q (type %q) in folder %q; add an id column or the personal owner", len(ids), name, typ, folder)
}
