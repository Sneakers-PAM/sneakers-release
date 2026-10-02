// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeKratos is a minimal in-memory stand-in for the Kratos admin API, enough
// to exercise paging, create, lookup, password set and delete.
type fakeKratos struct {
	mu   sync.Mutex
	ids  []Identity
	next int
	last map[string]any
}

func (f *fakeKratos) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/identities", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if ident := r.URL.Query().Get("credentials_identifier"); ident != "" {
			var out []Identity
			for _, i := range f.ids {
				if strings.Contains(string(i.Traits), `"`+ident+`"`) {
					out = append(out, i)
				}
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		start := 0
		if tok := r.URL.Query().Get("page_token"); tok != "" {
			_, _ = fmt.Sscanf(tok, "p%d", &start)
		}
		end := start + 2
		if end > len(f.ids) {
			end = len(f.ids)
		}
		page := f.ids[start:end]
		if r.URL.Query().Get("include_credential") != "password" {
			stripped := make([]Identity, len(page))
			for i, id := range page {
				id.Credentials = nil
				stripped[i] = id
			}
			page = stripped
		}
		if end < len(f.ids) {
			w.Header().Set("Link", fmt.Sprintf(`</admin/identities?page_size=2&page_token=p%d>; rel="next"`, end))
		}
		_ = json.NewEncoder(w).Encode(page)
	})
	mux.HandleFunc("POST /admin/identities", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.last = body
		f.next++
		traits, _ := json.Marshal(body["traits"])
		id := Identity{ID: fmt.Sprintf("new-%d", f.next), SchemaID: "default", State: "active", Traits: traits}
		f.ids = append(f.ids, id)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(id)
	})
	mux.HandleFunc("GET /admin/identities/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, i := range f.ids {
			if i.ID == r.PathValue("id") {
				_ = json.NewEncoder(w).Encode(i)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("PUT /admin/identities/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.last = body
		_ = json.NewEncoder(w).Encode(map[string]string{"id": r.PathValue("id")})
	})
	mux.HandleFunc("DELETE /admin/identities/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, id := range f.ids {
			if id.ID == r.PathValue("id") {
				f.ids = append(f.ids[:i], f.ids[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("GET /admin/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"v1.3.1"}`))
	})
	return mux
}

func seeded(n int) *fakeKratos {
	f := &fakeKratos{}
	for i := 0; i < n; i++ {
		f.ids = append(f.ids, Identity{
			ID: fmt.Sprintf("old-%d", i), SchemaID: "default", State: "active",
			Traits:      json.RawMessage(fmt.Sprintf(`{"email":"user%d@example.org"}`, i)),
			Credentials: map[string]Credential{"password": {Type: "password", Config: json.RawMessage(fmt.Sprintf(`{"hashed_password":"$2a$10$fakehash%d"}`, i))}},
		})
	}
	return f
}

func TestListPagesAndCarriesHashes(t *testing.T) {
	f := seeded(5)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	got, err := New(srv.URL).List(context.Background(), true)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("List returned %d identities, want 5 across three pages", len(got))
	}
	if got[4].PasswordHash() != "$2a$10$fakehash4" {
		t.Fatalf("hash = %q", got[4].PasswordHash())
	}
	plain, err := New(srv.URL).List(context.Background(), false)
	if err != nil || plain[0].PasswordHash() != "" {
		t.Fatalf("without credentials: %v, %q", err, plain[0].PasswordHash())
	}
}

func TestCreateFromSendsTheHashAndAddresses(t *testing.T) {
	f := &fakeKratos{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	src := seeded(1).ids[0]
	src.VerifiableAddresses = []Address{{Value: "user0@example.org", Via: "email", Verified: true}}
	src.RecoveryAddresses = []Address{{Value: "user0@example.org", Via: "email"}}
	src.MetadataAdmin = json.RawMessage(`null`)
	id, err := New(srv.URL).CreateFrom(context.Background(), src)
	if err != nil {
		t.Fatalf("CreateFrom: %v", err)
	}
	if id != "new-1" {
		t.Fatalf("id = %q", id)
	}
	creds := f.last["credentials"].(map[string]any)["password"].(map[string]any)["config"].(map[string]any)
	if creds["hashed_password"] != "$2a$10$fakehash0" {
		t.Fatalf("credentials sent = %v", creds)
	}
	va := f.last["verifiable_addresses"].([]any)[0].(map[string]any)
	if va["status"] != "completed" || va["verified"] != true {
		t.Fatalf("verifiable address sent = %v", va)
	}
	if _, ok := f.last["metadata_admin"]; ok {
		t.Fatal("a null metadata_admin must not be sent")
	}
}

func TestFindSetPasswordDeleteVersion(t *testing.T) {
	f := seeded(2)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	a := New(srv.URL)
	ctx := context.Background()
	id, err := a.FindByIdentifier(ctx, "user1@example.org")
	if err != nil || id != "old-1" {
		t.Fatalf("Find = %q, %v", id, err)
	}
	if _, err := a.FindByIdentifier(ctx, "nobody@example.org"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Find missing: %v", err)
	}
	if err := a.SetPassword(ctx, "old-1", "N3w-local"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	cfg := f.last["credentials"].(map[string]any)["password"].(map[string]any)["config"].(map[string]any)
	if cfg["password"] != "N3w-local" {
		t.Fatalf("password not sent: %v", cfg)
	}
	if err := a.SetPassword(ctx, "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetPassword missing: %v", err)
	}
	if err := a.Delete(ctx, "old-0"); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(ctx, "old-0"); err != nil {
		t.Fatalf("deleting a missing identity is not an error: %v", err)
	}
	if v, err := a.Version(ctx); err != nil || v != "v1.3.1" {
		t.Fatalf("Version = %q, %v", v, err)
	}
}

func TestRandomPassword(t *testing.T) {
	p, err := RandomPassword(24)
	if err != nil || len(p) != 24 {
		t.Fatalf("RandomPassword = %q, %v", p, err)
	}
	q, _ := RandomPassword(24)
	if p == q {
		t.Fatal("two random passwords matched")
	}
}
