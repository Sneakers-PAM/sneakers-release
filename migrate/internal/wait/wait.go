// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package wait blocks until sneakers-migrate's dependencies answer: a DNS
// name resolves, then each TCP target accepts a connection, in the order
// given. It retries forever on a fixed interval; the only time bound is the
// caller's own (an init container's timeout), never one this package sets.
package wait

import (
	"context"
	"net"
	"time"

	log "github.com/Bugs5382/go-log"
)

// Resolver looks up a DNS name. *net.Resolver satisfies it; tests use their
// own, so they never touch the real resolver. Dialing a TCP target needs no
// seam: tests point it at a local listener instead.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Config is one wait run.
type Config struct {
	// DNS is the name resolved before any --tcp target is dialed.
	DNS string
	// TCP is the host:port targets, dialed in this order.
	TCP []string
	// Every is how long to wait between retries of a target that isn't
	// answering yet.
	Every time.Duration
}

// Run resolves cfg.DNS, then dials each of cfg.TCP in order, retrying each on
// cfg.Every until it succeeds. It returns nil only once every target has
// answered, or ctx's error once ctx ends first.
func Run(ctx context.Context, cfg Config, r Resolver, lg log.Logger) error {
	if err := retryUntil(ctx, "dns "+cfg.DNS, cfg.Every, lg, func(c context.Context) error {
		_, err := r.LookupHost(c, cfg.DNS)
		return err
	}); err != nil {
		return err
	}
	var d net.Dialer
	for _, target := range cfg.TCP {
		if err := retryUntil(ctx, "tcp "+target, cfg.Every, lg, func(c context.Context) error {
			conn, err := d.DialContext(c, "tcp", target)
			if err != nil {
				return err
			}
			return conn.Close()
		}); err != nil {
			return err
		}
	}
	return nil
}

// retryUntil calls try until it succeeds or ctx ends, sleeping every between
// tries. Every try is logged with the target, its outcome and how long it
// took; never a value, only the target string and the error text.
func retryUntil(ctx context.Context, target string, every time.Duration, lg log.Logger, try func(context.Context) error) error {
	for {
		start := time.Now()
		err := try(ctx)
		elapsed := time.Since(start)
		if err == nil {
			lg.Info("wait: target answered", log.F("target", target), log.F("outcome", "ok"), log.F("elapsed_ms", elapsed.Milliseconds()))
			return nil
		}
		lg.Info("wait: target not ready", log.F("target", target), log.F("outcome", err.Error()), log.F("elapsed_ms", elapsed.Milliseconds()))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
