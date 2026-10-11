// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyConnectionWithAIA(t *testing.T) {
	root, rootKey := makeTestCertificate(t, x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               testName("root"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, nil)
	intermediate, intermediateKey := makeTestCertificate(t, x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               testName("intermediate"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, root, rootKey)

	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(intermediate.Raw)
	}))
	t.Cleanup(issuerServer.Close)

	leaf, _ := makeTestCertificate(t, x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               testName("leaf"),
		DNSNames:              []string{"example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: []string{issuerServer.URL},
	}, intermediate, intermediateKey)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, ServerName: "example.test"}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: state.ServerName, Roots: roots}); err == nil {
		t.Fatal("certificate unexpectedly verified without its intermediate")
	}
	if err := verifyConnectionWithAIA(context.Background(), state, roots, issuerServer.Client()); err != nil {
		t.Fatalf("certificate did not verify after fetching its intermediate: %v", err)
	}
}

func TestVerifyConnectionWithAIARejectsInvalidIssuer(t *testing.T) {
	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not a certificate"))
	}))
	t.Cleanup(issuerServer.Close)

	leaf, _ := makeTestCertificate(t, x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               testName("leaf"),
		DNSNames:              []string{"example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: []string{issuerServer.URL},
	}, nil, nil)

	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, ServerName: "example.test"}
	if err := verifyConnectionWithAIA(context.Background(), state, x509.NewCertPool(), issuerServer.Client()); err == nil {
		t.Fatal("invalid issuer response unexpectedly verified")
	}
}

func makeTestCertificate(t *testing.T, template x509.Certificate, parent *x509.Certificate, parentKey ed25519.PrivateKey) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating certificate key: %v", err)
	}
	if parent == nil {
		parent = &template
		parentKey = privateKey
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, parent, publicKey, parentKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return certificate, privateKey
}

func testName(commonName string) pkix.Name {
	return pkix.Name{CommonName: commonName}
}
