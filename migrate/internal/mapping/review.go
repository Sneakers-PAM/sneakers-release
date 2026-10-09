// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package mapping

import (
	"fmt"
	"io"
	"sort"
)

// Item is one secret as the review lists it: where it is, what it's called
// and its type. Never a value.
type Item struct {
	ID       string `json:"id"`
	Folder   Path   `json:"folder"`
	Owner    string `json:"owner,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	TargetID string `json:"target_id,omitempty"`
	Retired  bool   `json:"retired,omitempty"`
}

// ReviewReport lists every secret by folder, name and type, with counts, for
// the owner to decide the new structure from.
type ReviewReport struct {
	Secrets  []Item         `json:"secrets"`
	ByType   map[string]int `json:"by_type"`
	ByFolder map[string]int `json:"by_folder"`
	// UnusedTypes are types no secret uses.
	UnusedTypes []string `json:"unused_types"`
}

// Review lists the mapped rows' secrets.
func Review(r *Result) (*ReviewReport, error) {
	x := &remapper{r: r, folders: map[string]*folderNode{}, secrets: map[string]*secretNode{}, email: map[string]string{}, types: map[string]map[string]any{}}
	if err := x.load(); err != nil {
		return nil, err
	}
	rv := &ReviewReport{ByType: map[string]int{}, ByFolder: map[string]int{}}
	used := map[string]bool{}
	for _, id := range x.sOrder {
		d := x.secrets[id].data
		folder := str(d, "folderId")
		retired, _ := d["retired"].(bool)
		it := Item{ID: id, Folder: x.path(folder), Owner: x.ownerOf(folder), Name: str(d, "name"), Type: str(x.types[str(d, "typeId")], "name"), TargetID: str(d, "targetId"), Retired: retired}
		used[str(d, "typeId")] = true
		rv.Secrets = append(rv.Secrets, it)
		rv.ByType[it.Type]++
		rv.ByFolder[it.Folder.String()]++
	}
	for id, t := range x.types {
		if !used[id] {
			rv.UnusedTypes = append(rv.UnusedTypes, str(t, "name"))
		}
	}
	sort.Strings(rv.UnusedTypes)
	sort.SliceStable(rv.Secrets, func(i, j int) bool {
		a, b := rv.Secrets[i], rv.Secrets[j]
		if a.Folder.String() != b.Folder.String() {
			return a.Folder.String() < b.Folder.String()
		}
		return a.Name < b.Name
	})
	return rv, nil
}

// Template is a mapping file that keeps every secret where and as it is,
// one entry per secret, for the owner's decisions to be written into.
func (rv *ReviewReport) Template(bundleID string) *Plan {
	p := &Plan{Format: MappingFormat, Version: MappingVersion, Unlisted: UnlistedRefuse, BundleID: bundleID}
	for _, it := range rv.Secrets {
		p.Secrets = append(p.Secrets, SecretRule{ID: it.ID,
			From: Ref{Folder: it.Folder, Owner: it.Owner, Name: it.Name, Type: it.Type},
			To:   &Ref{Folder: it.Folder, Owner: it.Owner, Name: it.Name, Type: it.Type}})
	}
	return p
}

// Text writes the review for a person to read.
func (rv *ReviewReport) Text(w io.Writer) error {
	var err error
	f := func(format string, a ...any) {
		if err == nil {
			_, err = fmt.Fprintf(w, format, a...)
		}
	}
	f("%d secrets\n", len(rv.Secrets))
	for _, it := range rv.Secrets {
		owner := ""
		if it.Owner != "" {
			owner = " (personal: " + it.Owner + ")"
		}
		retired := ""
		if it.Retired {
			retired = " [retired]"
		}
		f("  %-14s %s%s | %s | %s%s\n", it.ID, it.Folder.String(), owner, it.Name, it.Type, retired)
	}
	f("by type:\n")
	for _, k := range sortedKeys(rv.ByType) {
		f("  %-36s %4d\n", k, rv.ByType[k])
	}
	f("by folder:\n")
	for _, k := range sortedKeys(rv.ByFolder) {
		f("  %-36s %4d\n", k, rv.ByFolder[k])
	}
	for _, t := range rv.UnusedTypes {
		f("unused type: %s\n", t)
	}
	return err
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
