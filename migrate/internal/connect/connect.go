// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package connect makes sneakers-migrate's first connection to each service
// it talks to (a database, a gRPC service, Kratos) wait until the service is
// reachable, for up to a minute. Each step runs as a fresh pod, and on an
// appliance the pod network can refuse a new pod's connections for a few
// seconds before its network policy admits it; one try would fail the step.
package connect

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
)

// Wait is how long a first connection keeps trying.
const Wait = 60 * time.Second

const (
	firstBackoff = 250 * time.Millisecond
	maxBackoff   = 5 * time.Second
	tryTimeout   = 5 * time.Second
)

// Retry calls try until it succeeds, wait has passed or ctx ends, sleeping
// between tries with a doubling backoff and jitter. Each failed try is logged
// at debug; the last error is returned with the target and the time spent.
func Retry(ctx context.Context, target string, wait time.Duration, lg log.Logger, try func(context.Context) error) error {
	start := time.Now()
	deadline := start.Add(wait)
	backoff := firstBackoff
	for n := 1; ; n++ {
		tctx, cancel := context.WithTimeout(ctx, tryTimeout)
		err := try(tctx)
		cancel()
		if err == nil {
			if n > 1 {
				lg.Info("connected after retries", log.F("target", target), log.F("tries", n), log.F("elapsed", time.Since(start).Round(time.Millisecond).String()))
			}
			return nil
		}
		elapsed := time.Since(start).Round(time.Millisecond)
		left := time.Until(deadline)
		if ctx.Err() != nil || left <= 0 {
			lg.Error(err, "connect failed", log.F("target", target), log.F("tries", n), log.F("elapsed", elapsed.String()))
			if ctx.Err() != nil {
				err = errors.Join(err, ctx.Err())
			}
			return fmt.Errorf("%s: no connection after %s (%d tries): %w", target, elapsed, n, err)
		}
		lg.Debug("connect retry", log.F("target", target), log.F("try", n), log.F("elapsed", elapsed.String()), log.F("error", err.Error()))
		sleep := min(backoff/2+rand.N(backoff), left) // #nosec G404 -- jitter, not a secret
		select {
		case <-ctx.Done():
		case <-time.After(sleep):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// Postgres opens a database, retrying the first connection (Retry).
func Postgres(ctx context.Context, target, dsn string, lg log.Logger) (*postgres.DB, error) {
	var db *postgres.DB
	err := Retry(ctx, target, Wait, lg, func(c context.Context) error {
		d, err := postgres.New(c, dsn)
		if err != nil {
			return err
		}
		db = d
		return nil
	})
	return db, err
}

// TCP waits until addr (host:port) accepts a connection, for a gRPC client
// whose connection is made lazily on its first call.
func TCP(ctx context.Context, target, addr string, wait time.Duration, lg log.Logger) error {
	var d net.Dialer
	return Retry(ctx, target+" at "+addr, wait, lg, func(c context.Context) error {
		conn, err := d.DialContext(c, "tcp", addr)
		if err != nil {
			return err
		}
		return conn.Close()
	})
}

// HTTP waits until url answers at all: any HTTP response means the service
// is reachable (its own errors are the caller's to handle).
func HTTP(ctx context.Context, target, url string, wait time.Duration, lg log.Logger) error {
	cl := &http.Client{Timeout: tryTimeout}
	return Retry(ctx, target+" at "+url, wait, lg, func(c context.Context) error {
		req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := cl.Do(req) // #nosec G107 G704 -- the operator-set service URL
		if err != nil {
			return err
		}
		return resp.Body.Close()
	})
}
