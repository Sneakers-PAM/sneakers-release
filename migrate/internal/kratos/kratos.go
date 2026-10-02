// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package kratos is a small client for the Ory Kratos admin API: listing
// identities with their password hashes, creating identities from those
// hashes, and the few calls import and verify need. It never logs a hash or a
// password.
package kratos

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ErrNotFound reports an identity that doesn't exist.
var ErrNotFound = errors.New("kratos: identity not found")

// Identity is an identity as the admin API returns it with
// include_credential=password.
type Identity struct {
	ID                  string                `json:"id"`
	SchemaID            string                `json:"schema_id"`
	State               string                `json:"state,omitempty"`
	Traits              json.RawMessage       `json:"traits"`
	MetadataPublic      json.RawMessage       `json:"metadata_public,omitempty"`
	MetadataAdmin       json.RawMessage       `json:"metadata_admin,omitempty"`
	VerifiableAddresses []Address             `json:"verifiable_addresses,omitempty"`
	RecoveryAddresses   []Address             `json:"recovery_addresses,omitempty"`
	Credentials         map[string]Credential `json:"credentials,omitempty"`
}

// Address is a verifiable or recovery address.
type Address struct {
	Value    string `json:"value"`
	Via      string `json:"via"`
	Verified bool   `json:"verified,omitempty"`
	Status   string `json:"status,omitempty"`
}

// Credential is one credential type on an identity.
type Credential struct {
	Type        string          `json:"type"`
	Identifiers []string        `json:"identifiers,omitempty"`
	Config      json.RawMessage `json:"config,omitempty"`
}

// PasswordHash returns the identity's password hash, if it has one.
func (i Identity) PasswordHash() string {
	c, ok := i.Credentials["password"]
	if !ok || len(c.Config) == 0 {
		return ""
	}
	var cfg struct {
		HashedPassword string `json:"hashed_password"`
	}
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return ""
	}
	return cfg.HashedPassword
}

// Admin calls one Kratos admin endpoint.
type Admin struct {
	base string
	http *http.Client
}

// New returns a client for the admin API at baseURL.
func New(baseURL string) *Admin {
	return &Admin{base: strings.TrimRight(baseURL, "/"), http: &http.Client{Timeout: 30 * time.Second}}
}

func (a *Admin) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := a.http.Do(req) // #nosec G107 G704 -- the operator-configured Kratos admin URL
	if err != nil {
		return nil, fmt.Errorf("kratos %s %s: %w", method, path, err)
	}
	return res, nil
}

func statusError(method, path string, res *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	var e struct {
		Error struct {
			Message string `json:"message"`
			Reason  string `json:"reason"`
		} `json:"error"`
	}
	detail := ""
	if json.Unmarshal(msg, &e) == nil && e.Error.Message != "" {
		detail = ": " + e.Error.Message
		if e.Error.Reason != "" {
			detail += " (" + e.Error.Reason + ")"
		}
	}
	return fmt.Errorf("kratos %s %s: status %d%s", method, path, res.StatusCode, detail)
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// List returns every identity, with password hashes when withPassword is set.
func (a *Admin) List(ctx context.Context, withPassword bool) ([]Identity, error) {
	q := url.Values{"page_size": {"500"}}
	if withPassword {
		q.Set("include_credential", "password")
	}
	path := "/admin/identities?" + q.Encode()
	var out []Identity
	for path != "" {
		res, err := a.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			err := statusError(http.MethodGet, "/admin/identities", res)
			_ = res.Body.Close()
			return nil, err
		}
		var page []Identity
		err = json.NewDecoder(res.Body).Decode(&page)
		_ = res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("kratos list: decode: %w", err)
		}
		out = append(out, page...)
		path = ""
		if m := nextLink.FindStringSubmatch(res.Header.Get("Link")); m != nil && len(page) > 0 {
			u, err := url.Parse(m[1])
			if err != nil {
				return nil, fmt.Errorf("kratos list: bad next link: %w", err)
			}
			// Keep this call's own parameters: a next link need not repeat them.
			nq := u.Query()
			for k, v := range q {
				if nq.Get(k) == "" {
					nq[k] = v
				}
			}
			path = u.EscapedPath() + "?" + nq.Encode()
		}
	}
	return out, nil
}

// CreateFrom creates a new identity carrying src's schema, state, traits,
// metadata, addresses and password hash, and returns the new id. Kratos
// assigns ids itself, so the id always changes.
func (a *Admin) CreateFrom(ctx context.Context, src Identity) (string, error) {
	body := map[string]any{"schema_id": src.SchemaID, "traits": src.Traits}
	if src.State != "" {
		body["state"] = src.State
	}
	if len(src.MetadataPublic) > 0 && string(src.MetadataPublic) != "null" {
		body["metadata_public"] = src.MetadataPublic
	}
	if len(src.MetadataAdmin) > 0 && string(src.MetadataAdmin) != "null" {
		body["metadata_admin"] = src.MetadataAdmin
	}
	if len(src.VerifiableAddresses) > 0 {
		va := make([]Address, 0, len(src.VerifiableAddresses))
		for _, v := range src.VerifiableAddresses {
			if v.Status == "" {
				v.Status = "pending"
				if v.Verified {
					v.Status = "completed"
				}
			}
			va = append(va, v)
		}
		body["verifiable_addresses"] = va
	}
	if len(src.RecoveryAddresses) > 0 {
		ra := make([]Address, 0, len(src.RecoveryAddresses))
		for _, r := range src.RecoveryAddresses {
			ra = append(ra, Address{Value: r.Value, Via: r.Via})
		}
		body["recovery_addresses"] = ra
	}
	if h := src.PasswordHash(); h != "" {
		body["credentials"] = map[string]any{"password": map[string]any{"config": map[string]string{"hashed_password": h}}}
	}
	res, err := a.do(ctx, http.MethodPost, "/admin/identities", body)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		return "", statusError(http.MethodPost, "/admin/identities", res)
	}
	var out Identity
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("kratos create: decode: %w", err)
	}
	return out.ID, nil
}

// CreateWithPassword creates an identity with the default schema, the given
// traits and a password Kratos hashes itself. The synthetic source uses it.
func (a *Admin) CreateWithPassword(ctx context.Context, email, first, last, password string) (string, error) {
	traits, err := json.Marshal(map[string]string{"email": email, "first_name": first, "last_name": last})
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"schema_id": "default", "state": "active", "traits": json.RawMessage(traits),
		"verifiable_addresses": []Address{{Value: email, Via: "email", Verified: true, Status: "completed"}},
		"credentials":          map[string]any{"password": map[string]any{"config": map[string]string{"password": password}}},
	}
	res, err := a.do(ctx, http.MethodPost, "/admin/identities", body)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		return "", statusError(http.MethodPost, "/admin/identities", res)
	}
	var out Identity
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("kratos create: decode: %w", err)
	}
	return out.ID, nil
}

// FindByIdentifier returns the id of the identity whose credentials use the
// identifier (an email here).
func (a *Admin) FindByIdentifier(ctx context.Context, identifier string) (string, error) {
	path := "/admin/identities?" + url.Values{"credentials_identifier": {identifier}}.Encode()
	res, err := a.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return "", statusError(http.MethodGet, "/admin/identities", res)
	}
	var out []Identity
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("kratos find: decode: %w", err)
	}
	if len(out) == 0 {
		return "", ErrNotFound
	}
	return out[0].ID, nil
}

func (a *Admin) get(ctx context.Context, id string) (Identity, error) {
	path := "/admin/identities/" + url.PathEscape(id)
	res, err := a.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusNotFound {
		return Identity{}, ErrNotFound
	}
	if res.StatusCode != http.StatusOK {
		return Identity{}, statusError(http.MethodGet, "/admin/identities/{id}", res)
	}
	var out Identity
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return Identity{}, fmt.Errorf("kratos get: decode: %w", err)
	}
	return out, nil
}

// SetPassword replaces an identity's password.
func (a *Admin) SetPassword(ctx context.Context, id, password string) error {
	cur, err := a.get(ctx, id)
	if err != nil {
		return err
	}
	body := map[string]any{
		"schema_id": cur.SchemaID, "state": cur.State, "traits": cur.Traits,
		"credentials": map[string]any{"password": map[string]any{"config": map[string]string{"password": password}}},
	}
	path := "/admin/identities/" + url.PathEscape(id)
	res, err := a.do(ctx, http.MethodPut, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return statusError(http.MethodPut, "/admin/identities/{id}", res)
	}
	return nil
}

// Delete removes an identity. A missing identity is not an error.
func (a *Admin) Delete(ctx context.Context, id string) error {
	path := "/admin/identities/" + url.PathEscape(id)
	res, err := a.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	switch res.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return nil
	}
	return statusError(http.MethodDelete, "/admin/identities/{id}", res)
}

// Version returns the Kratos version the admin API reports.
func (a *Admin) Version(ctx context.Context) (string, error) {
	res, err := a.do(ctx, http.MethodGet, "/admin/version", nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return "", statusError(http.MethodGet, "/admin/version", res)
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return "", fmt.Errorf("kratos version: decode: %w", err)
	}
	return v.Version, nil
}

// RandomPassword returns a random password of n characters from an
// unambiguous alphabet.
func RandomPassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_"
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[x.Int64()]
	}
	return string(b), nil
}
