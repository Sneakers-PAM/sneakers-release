// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package bundle is the migration bundle: a manifest plus one newline-delimited
// JSON stream per table, packed as a gzipped tar and encrypted with age
// (X25519) to the target's import key. The bundle is built and read in memory
// and only ever written to disk encrypted.
package bundle

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

// Format names the bundle format; FormatVersion is its version. Readers accept
// any minor version of their own major.
const (
	Format        = "sneakers-migrate-bundle"
	FormatVersion = "1.1"
	formatMajor   = "1"
	manifestName  = "manifest.json"
	streamPrefix  = "streams/"
	streamSuffix  = ".ndjson"
	maxEntryBytes = 2 << 30
)

var (
	// ErrDecrypt reports a bundle the given key can't open.
	ErrDecrypt = errors.New("bundle: cannot decrypt with this key")
	// ErrIntegrity reports a stream that doesn't match the manifest.
	ErrIntegrity = errors.New("bundle: integrity check failed")
	// ErrVersion reports a bundle of another format or major version.
	ErrVersion = errors.New("bundle: unsupported format version")
)

var streamName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// Manifest describes the bundle. It carries ids and counts, never values,
// apart from SampleKey, the per-bundle key for the sample-reveal HMACs, which
// is only ever inside the encrypted bundle.
type Manifest struct {
	Format        string            `json:"format"`
	FormatVersion string            `json:"format_version"`
	BundleID      string            `json:"bundle_id"`
	CreatedAt     string            `json:"created_at"`
	Profile       string            `json:"source_profile"`
	SourceVersion map[string]string `json:"source_versions"`
	Tables        []Table           `json:"tables"`
	AuditHead     Head              `json:"audit_head"`
	SampleKey     []byte            `json:"sample_key,omitempty"`
	Samples       []Sample          `json:"samples,omitempty"`
	NotCarried    []NotCarried      `json:"not_carried,omitempty"`
	// CurrentOnly: each secret carries its current value only, no history.
	CurrentOnly bool `json:"current_only,omitempty"`
	// SignInReset: no password hash, TOTP seed or passkey travels; every
	// user sets a password and enrols a second factor again.
	SignInReset bool `json:"sign_in_reset,omitempty"`
	// Sanitised: every value is a generated fake (a lab dry run).
	Sanitised bool `json:"sanitised,omitempty"`
	// Parity is each category's count in the source next to the bundle's.
	Parity []ParityCount `json:"parity,omitempty"`
}

// ParityCount is one category (folders, secrets, ...) counted in the source
// and in the bundle.
type ParityCount struct {
	Name   string `json:"name"`
	Stream string `json:"stream"`
	Source int    `json:"source"`
	Bundle int    `json:"bundle"`
}

// Table is one stream: its row count and the sha256 of its bytes.
type Table struct {
	Name   string `json:"name"`
	Rows   int    `json:"rows"`
	SHA256 string `json:"sha256"`
}

// Head is the last audit record of the source chain.
type Head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// Sample is one designated test value: verify reveals it from the target and
// compares HMACs, so the value itself is never printed or stored in clear.
type Sample struct {
	SecretID string `json:"secret_id"`
	Version  int    `json:"version"` // 0: the current value
	Field    string `json:"field"`
	HMAC     string `json:"hmac"`
}

// NotCarried lists source data the bundle leaves out on purpose, and why.
type NotCarried struct {
	Name   string `json:"name"`
	Rows   int    `json:"rows"`
	Reason string `json:"reason"`
}

// Table returns the manifest entry for a stream.
func (m Manifest) Table(name string) (Table, bool) {
	for _, t := range m.Tables {
		if t.Name == name {
			return t, true
		}
	}
	return Table{}, false
}

// Bundle is a manifest and its streams, in memory.
type Bundle struct {
	Manifest Manifest
	streams  map[string]*Stream
}

// Stream accumulates one table's rows as NDJSON.
type Stream struct {
	buf  bytes.Buffer
	rows int
}

// New starts an empty bundle with a fresh id.
func New(profile string) *Bundle {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &Bundle{
		Manifest: Manifest{
			Format: Format, FormatVersion: FormatVersion, BundleID: hex.EncodeToString(id),
			CreatedAt: time.Now().UTC().Format(time.RFC3339), Profile: profile,
			SourceVersion: map[string]string{},
		},
		streams: map[string]*Stream{},
	}
}

// Stream returns the named stream, creating it. Names are "<service>.<table>"
// and fixed in code, so a bad name is a programming error.
func (b *Bundle) Stream(name string) *Stream {
	if !streamName.MatchString(name) {
		panic("bundle: bad stream name " + name)
	}
	s, ok := b.streams[name]
	if !ok {
		s = &Stream{}
		b.streams[name] = s
	}
	return s
}

// Add appends one row.
func (s *Stream) Add(row any) error {
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	return s.AddRaw(raw)
}

// AddRaw appends one row already encoded as a single line of JSON.
func (s *Stream) AddRaw(raw []byte) error {
	if bytes.IndexByte(raw, '\n') >= 0 {
		return errors.New("bundle: a row must be one line of JSON")
	}
	s.buf.Write(raw)
	s.buf.WriteByte('\n')
	s.rows++
	return nil
}

// Rows is the stream's row count.
func (s *Stream) Rows() int { return s.rows }

// Names lists the bundle's streams, sorted.
func (b *Bundle) Names() []string {
	out := make([]string, 0, len(b.streams))
	for n := range b.streams {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Has reports whether the bundle carries a stream.
func (b *Bundle) Has(name string) bool { _, ok := b.streams[name]; return ok }

// Each calls fn with each row of a stream, in order. A missing stream has no rows.
func (b *Bundle) Each(name string, fn func(raw []byte) error) error {
	s, ok := b.streams[name]
	if !ok {
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(s.buf.Bytes()))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Seal fills the manifest's table list from the streams.
func (b *Bundle) Seal() error {
	b.Manifest.Tables = b.Manifest.Tables[:0]
	for _, n := range b.Names() {
		s := b.streams[n]
		sum := sha256.Sum256(s.buf.Bytes())
		b.Manifest.Tables = append(b.Manifest.Tables, Table{Name: n, Rows: s.rows, SHA256: hex.EncodeToString(sum[:])})
	}
	return nil
}

// check verifies every stream against the manifest and the reverse.
func (b *Bundle) check() error {
	seen := map[string]bool{}
	for _, t := range b.Manifest.Tables {
		s, ok := b.streams[t.Name]
		if !ok {
			return fmt.Errorf("%w: stream %s is missing", ErrIntegrity, t.Name)
		}
		sum := sha256.Sum256(s.buf.Bytes())
		if hex.EncodeToString(sum[:]) != t.SHA256 || s.rows != t.Rows {
			return fmt.Errorf("%w: stream %s does not match its checksum or count", ErrIntegrity, t.Name)
		}
		seen[t.Name] = true
	}
	for n := range b.streams {
		if !seen[n] {
			return fmt.Errorf("%w: stream %s is not in the manifest", ErrIntegrity, n)
		}
	}
	return nil
}

// Write seals the manifest and writes the encrypted bundle to w.
func Write(w io.Writer, b *Bundle, recipients ...age.Recipient) error {
	if err := b.Seal(); err != nil {
		return err
	}
	enc, err := age.Encrypt(w, recipients...)
	if err != nil {
		return fmt.Errorf("bundle: encrypt: %w", err)
	}
	gz := gzip.NewWriter(enc)
	tw := tar.NewWriter(gz)
	manifest, err := json.MarshalIndent(b.Manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeEntry(tw, manifestName, manifest); err != nil {
		return err
	}
	for _, n := range b.Names() {
		if err := writeEntry(tw, streamPrefix+n+streamSuffix, b.streams[n].buf.Bytes()); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return enc.Close()
}

func writeEntry(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// Read decrypts r, checks the format version and every stream's checksum, and
// returns the bundle.
func Read(r io.Reader, identities ...age.Identity) (*Bundle, error) {
	dec, err := age.Decrypt(r, identities...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	gz, err := gzip.NewReader(dec)
	if err != nil {
		return nil, fmt.Errorf("%w: not a bundle: %w", ErrIntegrity, err)
	}
	tr := tar.NewReader(gz)
	b := &Bundle{streams: map[string]*Stream{}}
	var haveManifest bool
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrIntegrity, err)
		}
		if h.Size > maxEntryBytes {
			return nil, fmt.Errorf("%w: entry %s is too large", ErrIntegrity, h.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxEntryBytes))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrIntegrity, err)
		}
		switch {
		case h.Name == manifestName:
			if err := json.Unmarshal(data, &b.Manifest); err != nil {
				return nil, fmt.Errorf("%w: manifest: %w", ErrIntegrity, err)
			}
			haveManifest = true
		case strings.HasPrefix(h.Name, streamPrefix) && strings.HasSuffix(h.Name, streamSuffix):
			name := strings.TrimSuffix(strings.TrimPrefix(h.Name, streamPrefix), streamSuffix)
			if !streamName.MatchString(name) {
				return nil, fmt.Errorf("%w: bad stream name %q", ErrIntegrity, name)
			}
			s := &Stream{}
			s.buf.Write(data)
			s.rows = bytes.Count(data, []byte{'\n'})
			b.streams[name] = s
		default:
			return nil, fmt.Errorf("%w: unexpected entry %q", ErrIntegrity, h.Name)
		}
	}
	if !haveManifest {
		return nil, fmt.Errorf("%w: no manifest", ErrIntegrity)
	}
	major, _, _ := strings.Cut(b.Manifest.FormatVersion, ".")
	if b.Manifest.Format != Format || major != formatMajor {
		return nil, fmt.Errorf("%w: %s %s (this tool reads %s %s.x)", ErrVersion, b.Manifest.Format, b.Manifest.FormatVersion, Format, formatMajor)
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseRecipient parses an age X25519 recipient ("age1...").
func ParseRecipient(s string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("bundle: bad recipient: %w", err)
	}
	return r, nil
}

// ParseIdentities reads age identities from an identity file.
func ParseIdentities(r io.Reader) ([]age.Identity, error) {
	ids, err := age.ParseIdentities(r)
	if err != nil {
		return nil, fmt.Errorf("bundle: bad identity file: %w", err)
	}
	return ids, nil
}

// decode is a strict JSON decode used by readers of bundle rows.
func decode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(v)
}

// Decode decodes one row, keeping numbers exact.
func Decode(raw []byte, v any) error { return decode(raw, v) }
