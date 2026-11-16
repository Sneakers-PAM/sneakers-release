// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wait

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
)

func testLogger() log.Logger {
	return log.NewLogger("wait-test")
}

// countingResolver fails failUntil calls, then succeeds, and reports how
// many times it was called.
type countingResolver struct {
	mu        sync.Mutex
	calls     int
	failUntil int // a negative value never succeeds
}

func (r *countingResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	r.mu.Lock()
	r.calls++
	n := r.calls
	r.mu.Unlock()
	if r.failUntil < 0 || n <= r.failUntil {
		return nil, errors.New("nxdomain")
	}
	return []string{"127.0.0.1"}, nil
}

func (r *countingResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// acceptingListener starts a TCP listener on loopback, sends label on each
// connection it accepts and then closes it, and returns the listener's
// address. The caller stops it with the returned func.
func acceptingListener(t *testing.T, label string, accepted chan<- string) (addr string, stop func()) {
	t.Helper()
	return acceptingListenerAt(t, "127.0.0.1:0", label, accepted)
}

// acceptingListenerAt is acceptingListener on a given address.
func acceptingListenerAt(t *testing.T, listenAddr, label string, accepted chan<- string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
			select {
			case accepted <- label:
			case <-done:
				return
			}
		}
	}()
	return ln.Addr().String(), func() { close(done); _ = ln.Close() }
}

// The second target's listener comes up only after the first has accepted, so a
// connection to the second can only be accepted after the first one: the order
// is causal, not a race between two accept goroutines. A Run that dialed the
// second target first would wait on it, never reach the first, and time out.
func TestRunDialsTargetsInGivenOrder(t *testing.T) {
	accepted := make(chan string, 4)
	addr1, stop1 := acceptingListener(t, "t1", accepted)
	defer stop1()
	// Reserve the second address without listening on it: dials to it are refused until it comes up.
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr2 := reserve.Addr().String()
	if err := reserve.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	r := &countingResolver{}
	cfg := Config{DNS: "kubernetes.default.svc.cluster.local", TCP: []string{addr1, addr2}, Every: 2 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, r, testLogger()) }()

	select {
	case got := <-accepted:
		if got != "t1" {
			t.Fatalf("first accepted = %q, want t1", got)
		}
	case err := <-done:
		t.Fatalf("Run returned %v before the first target accepted anything", err)
	case <-time.After(2 * time.Second):
		t.Fatal("the first target was never dialed first")
	}
	_, stop2 := acceptingListenerAt(t, addr2, "t2", accepted)
	defer stop2()

	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := <-accepted; got != "t2" {
		t.Fatalf("second accepted = %q, want t2", got)
	}
	if r.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want 1 (DNS resolves once)", r.callCount())
	}
}

func TestRunNeverDialsTCPWhileDNSUnresolved(t *testing.T) {
	accepted := make(chan string, 1)
	addr, stop := acceptingListener(t, "t1", accepted)
	defer stop()

	r := &countingResolver{failUntil: -1} // DNS never resolves
	cfg := Config{DNS: "kubernetes.default.svc.cluster.local", TCP: []string{addr}, Every: 2 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := Run(ctx, cfg, r, testLogger())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run: %v, want context.DeadlineExceeded", err)
	}
	select {
	case label := <-accepted:
		t.Fatalf("TCP target %q was dialed before DNS ever resolved", label)
	default:
	}
}

func TestRunRetriesDNSUntilItResolves(t *testing.T) {
	accepted := make(chan string, 1)
	addr, stop := acceptingListener(t, "t1", accepted)
	defer stop()

	r := &countingResolver{failUntil: 3}
	cfg := Config{DNS: "kubernetes.default.svc.cluster.local", TCP: []string{addr}, Every: 2 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Run(ctx, cfg, r, testLogger()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := r.callCount(); got != 4 {
		t.Fatalf("resolver calls = %d, want 4 (3 failures then success)", got)
	}
}

// With no TCP target, Run retries the DNS name through its failures and
// returns once it resolves.
func TestRunWithDNSOnlyRetriesThenReturns(t *testing.T) {
	r := &countingResolver{failUntil: 3}
	cfg := Config{DNS: "kubernetes.default.svc.cluster.local", Every: 2 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Run(ctx, cfg, r, testLogger()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := r.callCount(); got != 4 {
		t.Fatalf("resolver calls = %d, want 4 (3 failures then success)", got)
	}
}

func TestRunRetriesTCPUntilItConnects(t *testing.T) {
	// Reserve a free port, then close it so the first dials refuse, and
	// reopen the same port a little later: like a service that isn't ready
	// at the first few tries.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	accepted := make(chan string, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		ln2, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		defer func() { _ = ln2.Close() }()
		conn, err := ln2.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
		accepted <- "t1"
	}()

	r := &countingResolver{}
	cfg := Config{DNS: "kubernetes.default.svc.cluster.local", TCP: []string{addr}, Every: 2 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Run(ctx, cfg, r, testLogger()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("the target was never dialed once it started listening")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	r := &countingResolver{failUntil: -1}
	cfg := Config{DNS: "kubernetes.default.svc.cluster.local", TCP: []string{"127.0.0.1:1"}, Every: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, r, testLogger()) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run after cancel: %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after the context was canceled")
	}
}
