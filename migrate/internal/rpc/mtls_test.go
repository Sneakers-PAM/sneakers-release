// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mtls "github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// testCA is a throwaway CA that signs leaf files into a directory.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf writes tls.crt, tls.key and ca.crt for a certificate valid for both uses.
func (c *testCA) leaf(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	write := func(name string, blob []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), blob, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write("tls.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	write("ca.crt", c.pem)
}

func setMTLSEnv(t *testing.T, dir string) {
	t.Helper()
	t.Setenv(mtls.EnvCertFile, filepath.Join(dir, "tls.crt"))
	t.Setenv(mtls.EnvKeyFile, filepath.Join(dir, "tls.key"))
	t.Setenv(mtls.EnvCAFile, filepath.Join(dir, "ca.crt"))
}

func clearMTLSEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{mtls.EnvCertFile, mtls.EnvKeyFile, mtls.EnvCAFile} {
		t.Setenv(k, "")
	}
}

// serveMTLS runs a health server that requires a client certificate from ca.
func serveMTLS(t *testing.T, ca *testCA) string {
	t.Helper()
	dir := t.TempDir()
	ca.leaf(t, dir)
	p, err := mtls.NewProvider(mtls.Files{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.crt")})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(p.ServerOption())
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "localhost:" + strings.Split(lis.Addr().String(), ":")[1]
}

func check(addr string) error {
	cc, err := Dial(addr, "")
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestDialUsesMutualTLSWhenTheFilesAreSet(t *testing.T) {
	ca := newTestCA(t)
	addr := serveMTLS(t, ca)
	mine := t.TempDir()
	ca.leaf(t, mine)
	setMTLSEnv(t, mine)
	if err := check(addr); err != nil {
		t.Fatalf("a caller with a certificate from the cluster CA was refused: %v", err)
	}
}

func TestDialWithoutTheFilesIsPlaintextAndIsRefusedByAnMTLSServer(t *testing.T) {
	addr := serveMTLS(t, newTestCA(t))
	clearMTLSEnv(t)
	if err := check(addr); err == nil {
		t.Fatal("a plaintext caller reached an mTLS server")
	}
}

func TestDialRefusesAServerSignedByAnotherCA(t *testing.T) {
	addr := serveMTLS(t, newTestCA(t))
	mine := t.TempDir()
	newTestCA(t).leaf(t, mine)
	setMTLSEnv(t, mine)
	if err := check(addr); err == nil {
		t.Fatal("a server from another CA was trusted")
	}
}

func TestDialWithSomeOfTheFilesSetFailsAndNamesTheMissingOnes(t *testing.T) {
	clearMTLSEnv(t)
	t.Setenv(mtls.EnvCertFile, "/var/run/sneakers/tls/tls.crt")
	_, err := Dial("localhost:1", "")
	if err == nil || !strings.Contains(err.Error(), mtls.EnvKeyFile) || !strings.Contains(err.Error(), mtls.EnvCAFile) {
		t.Fatalf("a partial setting must fail naming what is missing, got %v", err)
	}
}

func TestDialWithAnUnreadableFileFails(t *testing.T) {
	setMTLSEnv(t, filepath.Join(t.TempDir(), "missing"))
	if _, err := Dial("localhost:1", ""); err == nil {
		t.Fatal("an unreadable certificate must fail the dial")
	}
}
