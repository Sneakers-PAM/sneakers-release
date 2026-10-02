// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package codes holds sneakers-migrate's error codes. A code rides the error
// chain (go-apperr), and the command line turns its range into an exit code.
package codes

import apperr "github.com/Bugs5382/go-apperr"

// The codes. 1xxx: the source refused; 2xxx: the target refused; 3xxx:
// verify found a mismatch; 4xxx: the bundle is unreadable or damaged.
const (
	SourceVersion  = 1001
	SourceChain    = 1002
	SourceValue    = 1003
	TargetVersion  = 2001
	TargetNotEmpty = 2002
	ModeRefused    = 2003
	TargetKey      = 2004
	VerifyMismatch = 3001
	BundleDamaged  = 4001
	BundleKey      = 4002
	BundleVersion  = 4003
)

// Entries describes every code, for the docs and the registry.
var Entries = []apperr.Entry{
	{Code: SourceVersion, Title: "source", Cause: "the source database is at a version this tool does not read, or a migration is dirty"},
	{Code: SourceChain, Title: "source", Cause: "the source audit chain does not verify"},
	{Code: SourceValue, Title: "source", Cause: "a source value does not open with the given keys"},
	{Code: TargetVersion, Title: "target", Cause: "the target database is not at the baseline this tool writes"},
	{Code: TargetNotEmpty, Title: "target", Cause: "the target already holds data that is not this bundle's"},
	{Code: ModeRefused, Title: "mode", Cause: "the flag is only allowed in rehearsal mode"},
	{Code: TargetKey, Title: "target", Cause: "a target key the import needs is missing or invalid"},
	{Code: VerifyMismatch, Title: "verify", Cause: "the target does not match the bundle"},
	{Code: BundleDamaged, Title: "bundle", Cause: "the bundle is damaged or does not match its manifest"},
	{Code: BundleKey, Title: "bundle", Cause: "the bundle does not open with the given identity"},
	{Code: BundleVersion, Title: "bundle", Cause: "the bundle is from another major version"},
}

// Registry is the code table.
func Registry() (*apperr.Registry, error) { return apperr.NewRegistry(Entries) }

// Wrap attaches a code to err.
func Wrap(code int, err error) error { return apperr.Coded(code, err) }

// Of returns the code on err's chain.
func Of(err error) (int, bool) { return apperr.Code(err) }
