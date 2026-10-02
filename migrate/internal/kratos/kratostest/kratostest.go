// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package kratostest is an in-memory stand-in for the Kratos admin API, for
// tests: list (paged, with password hashes on request), create (from a hash or
// a password), get, replace, delete, lookup by identifier and version.
package kratostest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Server is the fake admin API.
type Server struct {
	*httptest.Server
	mu  sync.Mutex
	ids []map[string]any
	n   int
	// Passwords maps an identity id to the last plaintext password set, so a
	// test can check a password reset without a real hash.
	Passwords map[string]string
}

// New starts a fake admin API.
func New() *Server {
	s := &Server{Passwords: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/identities", s.list)
	mux.HandleFunc("POST /admin/identities", s.create)
	mux.HandleFunc("GET /admin/identities/{id}", s.get)
	mux.HandleFunc("PUT /admin/identities/{id}", s.put)
	mux.HandleFunc("DELETE /admin/identities/{id}", s.del)
	mux.HandleFunc("GET /admin/version", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"version":"v1.3.1"}`)) })
	s.Server = httptest.NewServer(mux)
	return s
}

// Count is the number of identities.
func (s *Server) Count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.ids) }

func email(id map[string]any) string {
	t, _ := id["traits"].(map[string]any)
	e, _ := t["email"].(string)
	return e
}

func strip(id map[string]any, withPassword bool) map[string]any {
	out := map[string]any{}
	for k, v := range id {
		out[k] = v
	}
	if !withPassword {
		delete(out, "credentials")
	}
	return out
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	withPw := r.URL.Query().Get("include_credential") == "password"
	if ident := r.URL.Query().Get("credentials_identifier"); ident != "" {
		out := []map[string]any{}
		for _, id := range s.ids {
			if strings.EqualFold(email(id), ident) {
				out = append(out, strip(id, false))
			}
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	start := 0
	if tok := r.URL.Query().Get("page_token"); tok != "" {
		_, _ = fmt.Sscanf(tok, "p%d", &start)
	}
	end := start + 7
	if end > len(s.ids) {
		end = len(s.ids)
	}
	page := []map[string]any{}
	for _, id := range s.ids[start:end] {
		page = append(page, strip(id, withPw))
	}
	if end < len(s.ids) {
		w.Header().Set("Link", fmt.Sprintf(`</admin/identities?page_size=7&page_token=p%d>; rel="next"`, end))
	}
	_ = json.NewEncoder(w).Encode(page)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":{"message":"bad json"}}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.ids {
		if strings.EqualFold(email(id), email(body)) {
			http.Error(w, `{"error":{"message":"identity exists"}}`, http.StatusConflict)
			return
		}
	}
	s.n++
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", s.n)
	body["id"] = id
	if body["state"] == nil {
		body["state"] = "active"
	}
	if creds, ok := body["credentials"].(map[string]any); ok {
		if pw, ok := creds["password"].(map[string]any); ok {
			cfg, _ := pw["config"].(map[string]any)
			if p, ok := cfg["password"].(string); ok {
				s.Passwords[id] = p
				cfg = map[string]any{"hashed_password": "$2a$10$fake." + id}
			}
			body["credentials"] = map[string]any{"password": map[string]any{"type": "password", "identifiers": []string{email(body)}, "config": cfg}}
		}
	}
	s.ids = append(s.ids, body)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(strip(body, false))
}

func (s *Server) find(id string) (int, bool) {
	for i, v := range s.ids {
		if v["id"] == id {
			return i, true
		}
	}
	return 0, false
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.find(r.PathValue("id"))
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(strip(s.ids[i], r.URL.Query().Get("include_credential") == "password"))
}

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.find(r.PathValue("id"))
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if creds, ok := body["credentials"].(map[string]any); ok {
		if pw, ok := creds["password"].(map[string]any); ok {
			cfg, _ := pw["config"].(map[string]any)
			if p, ok := cfg["password"].(string); ok {
				s.Passwords[r.PathValue("id")] = p
			}
		}
	}
	_ = json.NewEncoder(w).Encode(strip(s.ids[i], false))
}

func (s *Server) del(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.find(r.PathValue("id"))
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.ids = append(s.ids[:i], s.ids[i+1:]...)
	w.WriteHeader(http.StatusNoContent)
}
