// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package connect_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/connect"
)

// refuseThenAccept returns an address that refuses connections for d, then
// accepts them (a pod network that admits a new pod a few seconds late).
func refuseThenAccept(t *testing.T, d time.Duration) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	go func() {
		time.Sleep(d)
		l2, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = l2.Close() })
		for {
			c, err := l2.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return addr
}

func TestTCPWaitsUntilTheAddressAccepts(t *testing.T) {
	addr := refuseThenAccept(t, 1500*time.Millisecond)
	start := time.Now()
	if err := connect.TCP(context.Background(), "the target vault", addr, 10*time.Second, log.Nop()); err != nil {
		t.Fatalf("TCP: %v", err)
	}
	if el := time.Since(start); el < 1400*time.Millisecond {
		t.Fatalf("connected after %v, before the address accepted", el)
	}
}

func TestTCPGivesUpAfterTheWaitNamingTheTargetAndTheTime(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	start := time.Now()
	err := connect.TCP(context.Background(), "the target vault", addr, time.Second, log.Nop())
	if err == nil {
		t.Fatal("connected to an address that never accepts")
	}
	if el := time.Since(start); el < time.Second || el > 4*time.Second {
		t.Fatalf("gave up after %v, want about 1s", el)
	}
	if !strings.Contains(err.Error(), "the target vault") || !strings.Contains(err.Error(), addr) || !strings.Contains(err.Error(), "after") {
		t.Fatalf("error doesn't name the target, the address and the time: %v", err)
	}
}

func TestRetryStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := connect.Retry(ctx, "the target database", time.Minute, log.Nop(), func(context.Context) error { return errors.New("refused") })
	if err == nil {
		t.Fatal("no error after the context ended")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("kept retrying %v after the context ended", el)
	}
}

func TestRetryReturnsOnTheFirstSuccess(t *testing.T) {
	n := 0
	err := connect.Retry(context.Background(), "the target database", 10*time.Second, log.Nop(), func(context.Context) error {
		n++
		if n < 3 {
			return errors.New("connection refused")
		}
		return nil
	})
	if err != nil || n != 3 {
		t.Fatalf("err %v after %d tries, want nil after 3", err, n)
	}
}

func TestHTTPWaitsForAnAnswer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + l.Addr().String()
	_ = l.Close()
	go func() {
		time.Sleep(time.Second)
		l2, err := net.Listen("tcp", strings.TrimPrefix(url, "http://"))
		if err != nil {
			return
		}
		srv.Listener = l2
		srv.Start()
	}()
	t.Cleanup(srv.Close)
	if err := connect.HTTP(context.Background(), "the target Kratos", url, 10*time.Second, log.Nop()); err != nil {
		t.Fatalf("HTTP: %v (any answer, even a 503, means the address is reachable)", err)
	}
}
