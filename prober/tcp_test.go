// Copyright 2015 The Prometheus Authors
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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestTCPConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	ch := make(chan (struct{}))
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		conn.Close()
		ch <- struct{}{}
	}()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), config.Module{TCP: config.TCPProbe{IPProtocolFallback: true}}, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch
}

func TestTCPConnectionFails(t *testing.T) {
	// Invalid port number.
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ProbeTCP(testCTX, ":0", config.Module{TCP: config.TCPProbe{}}, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module succeeded, expected failure.")
	}
}

func TestTCPConnectionWithTLS(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()
	_, listenPort, _ := net.SplitHostPort(ln.Addr().String())

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create test certificates valid for 1 day.
	certExpiry := time.Now().AddDate(0, 0, 1)
	rootCertTmpl := generateCertificateTemplate(certExpiry, false)
	rootCertTmpl.IsCA = true
	_, rootCertPem, rootKey := generateSelfSignedCertificate(rootCertTmpl)

	// CAFile must be passed via filesystem, use a tempfile.
	tmpCaFile, err := os.CreateTemp("", "cafile.pem")
	if err != nil {
		t.Fatalf("Error creating CA tempfile: %s", err)
	}
	if _, err := tmpCaFile.Write(rootCertPem); err != nil {
		t.Fatalf("Error writing CA tempfile: %s", err)
	}
	if err := tmpCaFile.Close(); err != nil {
		t.Fatalf("Error closing CA tempfile: %s", err)
	}
	defer os.Remove(tmpCaFile.Name())

	ch := make(chan (struct{}))
	logger := promslog.NewNopLogger()
	// Handle server side of this test.
	serverFunc := func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()

		rootKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey)})
		testcert, err := tls.X509KeyPair(rootCertPem, rootKeyPem)
		if err != nil {
			panic(fmt.Sprintf("Failed to decode TLS testing keypair: %s\n", err))
		}

		// Immediately upgrade to TLS.
		tlsConfig := &tls.Config{
			ServerName:   "localhost",
			Certificates: []tls.Certificate{testcert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		}
		tlsConn := tls.Server(conn, tlsConfig)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			logger.Error("Error TLS Handshake (server) failed", "err", err)
		} else {
			// Send some bytes before terminating the connection.
			fmt.Fprintf(tlsConn, "Hello World!\n")
		}
		ch <- struct{}{}
	}

	// Expect name-verified TLS connection.
	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			TLS:                true,
			TLSConfig: pconfig.TLSConfig{
				CAFile:             tmpCaFile.Name(),
				InsecureSkipVerify: false,
			},
		},
	}

	registry := prometheus.NewRegistry()
	go serverFunc()
	// Test name-verification failure (IP without IPs in cert's SAN).
	if ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module succeeded, expected failure.")
	}
	<-ch

	registry = prometheus.NewRegistry()
	go serverFunc()
	// Test name-verification with name from target.
	target := net.JoinHostPort("localhost", listenPort)
	if !ProbeTCP(testCTX, target, module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	registry = prometheus.NewRegistry()
	go serverFunc()
	// Test name-verification against name from tls_config.
	module.TCP.TLSConfig.ServerName = "localhost"
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	// Check the resulting metrics.
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	// Check labels
	expectedLabels := map[string]map[string]string{
		"probe_tls_version_info": {
			"version": "TLS 1.2",
		},
		"probe_tls_cipher_info": {
			"cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
	}
	checkRegistryLabels(expectedLabels, mfs, t)

	// Check values
	expectedResults := map[string]float64{
		"probe_ssl_earliest_cert_expiry": float64(certExpiry.Unix()),
		"probe_ssl_last_chain_info":      1,
		"probe_tls_version_info":         1,
		"probe_tls_cipher_info":          1,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

// tlsRequireClientCertServer starts a TLS listener that requires (but does not
// verify) a client certificate, restricted to a single TLS version. It never
// receives one from ProbeTCP, so the handshake fails with a version-specific
// alert: TLS 1.3 sends certificate_required (116), TLS 1.2 sends
// handshake_failure (40), since alert 42 (bad_certificate) is only sent for a
// certificate that was presented but rejected, not for a missing one.
func tlsRequireClientCertServer(t *testing.T, tlsVersion uint16) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	t.Cleanup(func() { ln.Close() })

	certExpiry := time.Now().AddDate(0, 0, 1)
	tmpl := generateCertificateTemplate(certExpiry, true)
	tmpl.IsCA = true
	_, certPem, key := generateSelfSignedCertificate(tmpl)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	serverCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatalf("Failed to decode TLS testing keypair: %s", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tlsVersion,
			MaxVersion:   tlsVersion,
		})
		defer tlsConn.Close()
		// The client never presents a certificate, so this always errors;
		// the alert it sent is what the test cares about.
		tlsConn.Handshake()
	}()

	return ln
}

func TestTCPConnectionWithExpectedTLSAlert(t *testing.T) {
	tests := []struct {
		name       string
		tlsVersion uint16
		alertCode  uint8
	}{
		{"TLS 1.3 sends certificate_required", tls.VersionTLS13, 116},
		{"TLS 1.2 sends handshake_failure", tls.VersionTLS12, 40},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ln := tlsRequireClientCertServer(t, test.tlsVersion)

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			module := config.Module{
				TCP: config.TCPProbe{
					IPProtocolFallback: true,
					TLS:                true,
					TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
					ValidTLSAlertCodes: []uint8{test.alertCode},
				},
			}

			registry := prometheus.NewRegistry()
			if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
				t.Fatalf("TCP module failed, expected success on expected TLS alert %d.", test.alertCode)
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_tls_alert_code": float64(test.alertCode),
			}
			checkRegistryResults(expectedResults, mfs, t)
		})
	}
}

func TestTCPConnectionWithUnexpectedTLSAlert(t *testing.T) {
	tests := []struct {
		name          string
		tlsVersion    uint16
		observedAlert uint8
	}{
		{"TLS 1.3 sends certificate_required", tls.VersionTLS13, 116},
		{"TLS 1.2 sends handshake_failure", tls.VersionTLS12, 40},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ln := tlsRequireClientCertServer(t, test.tlsVersion)

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			module := config.Module{
				TCP: config.TCPProbe{
					IPProtocolFallback: true,
					TLS:                true,
					TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
					// Listing only an unrelated code must make the probe fail,
					// regardless of which alert the server actually sent.
					ValidTLSAlertCodes: []uint8{200},
				},
			}

			registry := prometheus.NewRegistry()
			if ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
				t.Fatalf("TCP module succeeded, expected failure on unexpected TLS alert.")
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_tls_alert_code": float64(test.observedAlert),
			}
			checkRegistryResults(expectedResults, mfs, t)
		})
	}
}

func TestTCPConnectionSucceedsWithTLSAlertCodesConfiguredFails(t *testing.T) {
	certExpiry := time.Now().AddDate(0, 0, 1)
	tmpl := generateCertificateTemplate(certExpiry, true)
	tmpl.IsCA = true
	_, certPem, key := generateSelfSignedCertificate(tmpl)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	serverCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatalf("Failed to decode TLS testing keypair: %s", err)
	}

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{serverCert}})
		defer tlsConn.Close()
		// This handshake genuinely succeeds; the probe must still fail because
		// valid_tls_alert_codes means a rejection is expected.
		tlsConn.Handshake()
	}()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocolFallback: true,
			TLS:                true,
			TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
			ValidTLSAlertCodes: []uint8{116},
		},
	}

	registry := prometheus.NewRegistry()
	if ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module succeeded, expected failure because valid_tls_alert_codes requires rejection.")
	}
}

func TestTCPConnectionNonAlertFailureWithTLSAlertCodesConfigured(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	addr := ln.Addr().String()
	// Nothing listens on addr anymore, so dialing it fails at the TCP level
	// (connection refused) before any TLS handshake can occur.
	ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocolFallback: true,
			TLS:                true,
			TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
			ValidTLSAlertCodes: []uint8{116},
		},
	}

	registry := prometheus.NewRegistry()
	if ProbeTCP(testCTX, addr, module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module succeeded, expected failure on a non-TLS connection error.")
	}

	// The dial failed before any TLS alert could be observed.
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_tls_alert_code": 0,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

// tlsRejectClientCertServer starts a TLS listener that requires a client
// certificate and always rejects it via VerifyPeerCertificate, restricted to a
// single TLS version. Unlike the missing-certificate case above, bad_certificate
// (42) is sent for the same reason regardless of TLS version, since
// VerifyPeerCertificate is invoked from shared, version-independent code.
func tlsRejectClientCertServer(t *testing.T, tlsVersion uint16) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	t.Cleanup(func() { ln.Close() })

	certExpiry := time.Now().AddDate(0, 0, 1)
	tmpl := generateCertificateTemplate(certExpiry, true)
	tmpl.IsCA = true
	_, certPem, key := generateSelfSignedCertificate(tmpl)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	serverCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatalf("Failed to decode TLS testing keypair: %s", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tlsVersion,
			MaxVersion:   tlsVersion,
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return errors.New("reject: simulated bad certificate")
			},
		})
		defer tlsConn.Close()
		// The client's certificate is always rejected here, so this always
		// errors; the alert it sent is what the test cares about.
		tlsConn.Handshake()
	}()

	return ln
}

func TestTCPConnectionWithBadCertificateTLSAlert(t *testing.T) {
	tests := []struct {
		name       string
		tlsVersion uint16
	}{
		{"TLS 1.3 sends bad_certificate", tls.VersionTLS13},
		{"TLS 1.2 sends bad_certificate", tls.VersionTLS12},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ln := tlsRejectClientCertServer(t, test.tlsVersion)

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			module := config.Module{
				TCP: config.TCPProbe{
					IPProtocolFallback: true,
					TLS:                true,
					TLSConfig:          clientCertTLSConfig(t),
					ValidTLSAlertCodes: []uint8{42},
				},
			}

			registry := prometheus.NewRegistry()
			if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
				t.Fatalf("TCP module failed, expected success on expected TLS alert 42.")
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_tls_alert_code": 42,
			}
			checkRegistryResults(expectedResults, mfs, t)
		})
	}
}

// TestTCPConnectionWithExpectedTLSAlertReportsCertificateMetrics asserts that
// the TCP prober behaves exactly like the HTTP prober on the accepted-alert
// path: it must still capture the server's certificate and report the same
// TLS/certificate/CRL metrics as a genuinely successful TLS/TCP connection.
func TestTCPConnectionWithExpectedTLSAlertReportsCertificateMetrics(t *testing.T) {
	tests := []struct {
		name       string
		tlsVersion uint16
		alertCode  uint8
	}{
		{"TLS 1.3 sends certificate_required", tls.VersionTLS13, 116},
		{"TLS 1.2 sends handshake_failure", tls.VersionTLS12, 40},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leaf, leafKey, ca := newCRLLeafCert(t)
			ln := tlsRequireClientCertServerWithCert(t, test.tlsVersion, leaf, leafKey, ca)

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			module := config.Module{
				TCP: config.TCPProbe{
					IPProtocolFallback: true,
					TLS:                true,
					TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
					ValidTLSAlertCodes: []uint8{test.alertCode},
					CheckRevoked:       true,
				},
			}

			registry := prometheus.NewRegistry()
			if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
				t.Fatalf("TCP module failed, expected success on expected TLS alert %d.", test.alertCode)
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}

			expectedResults := map[string]float64{
				"probe_ssl_earliest_cert_expiry": float64(leaf.NotAfter.Unix()),
				"probe_tls_version_info":         1,
				"probe_tls_cipher_info":          1,
			}
			checkRegistryResults(expectedResults, mfs, t)

			leafSubject := leaf.Subject.String()
			if val, ok := getMetricWithLabels(mfs, "probe_ssl_last_chain_info", map[string]string{"subject": leafSubject}); !ok || val != 1 {
				t.Errorf("Expected probe_ssl_last_chain_info=1 with subject=%q, got %v (found=%v)", leafSubject, val, ok)
			}
			if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", map[string]string{"subject": leafSubject}); !ok || val != 1 {
				t.Errorf("Expected probe_ssl_crl_available=1 with subject=%q, got %v (found=%v)", leafSubject, val, ok)
			}
			if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_revoked", map[string]string{"subject": leafSubject}); !ok || val != 0 {
				t.Errorf("Expected probe_ssl_crl_revoked=0 with subject=%q, got %v (found=%v)", leafSubject, val, ok)
			}
		})
	}
}

func TestTCPConnectionWithTLSAndVerifiedCertificateChain(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()
	_, listenPort, _ := net.SplitHostPort(ln.Addr().String())

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// From here prepare two certificate chains where one expires before the
	// other

	rootPrivatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error creating rsa key: %s", err))
	}

	rootCertExpiry := time.Now().AddDate(0, 0, 3)
	rootCertTmpl := generateCertificateTemplate(rootCertExpiry, false)
	rootCertTmpl.IsCA = true
	_, rootCertPem := generateSelfSignedCertificateWithPrivateKey(rootCertTmpl, rootPrivatekey)

	olderRootCertExpiry := time.Now().AddDate(0, 0, 1)
	olderRootCertTmpl := generateCertificateTemplate(olderRootCertExpiry, false)
	olderRootCertTmpl.IsCA = true
	olderRootCert, olderRootCertPem := generateSelfSignedCertificateWithPrivateKey(olderRootCertTmpl, rootPrivatekey)

	serverCertExpiry := time.Now().AddDate(0, 0, 2)
	serverCertTmpl := generateCertificateTemplate(serverCertExpiry, false)
	_, serverCertPem, serverKey := generateSignedCertificate(serverCertTmpl, olderRootCert, rootPrivatekey)

	// CAFile must be passed via filesystem, use a tempfile.
	tmpCaFile, err := os.CreateTemp("", "cafile.pem")
	if err != nil {
		t.Fatalf("Error creating CA tempfile: %s", err)
	}
	if _, err := tmpCaFile.Write(bytes.Join([][]byte{rootCertPem, olderRootCertPem}, []byte("\n"))); err != nil {
		t.Fatalf("Error writing CA tempfile: %s", err)
	}
	if err := tmpCaFile.Close(); err != nil {
		t.Fatalf("Error closing CA tempfile: %s", err)
	}
	defer os.Remove(tmpCaFile.Name())

	ch := make(chan (struct{}))
	logger := promslog.NewNopLogger()
	// Handle server side of this test.
	serverFunc := func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()

		serverKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

		// Include the older root cert in the chain
		keypair, err := tls.X509KeyPair(append(serverCertPem, olderRootCertPem...), serverKeyPem)
		if err != nil {
			panic(fmt.Sprintf("Failed to decode TLS testing keypair: %s\n", err))
		}

		// Immediately upgrade to TLS.
		tlsConfig := &tls.Config{
			ServerName:   "localhost",
			Certificates: []tls.Certificate{keypair},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		}
		tlsConn := tls.Server(conn, tlsConfig)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			logger.Error("Error TLS Handshake (server) failed", "err", err)
		} else {
			// Send some bytes before terminating the connection.
			fmt.Fprintf(tlsConn, "Hello World!\n")
		}
		ch <- struct{}{}
	}

	// Expect name-verified TLS connection.
	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			TLS:                true,
			TLSConfig: pconfig.TLSConfig{
				CAFile:             tmpCaFile.Name(),
				InsecureSkipVerify: false,
			},
		},
	}

	registry := prometheus.NewRegistry()
	go serverFunc()
	// Test name-verification with name from target.
	target := net.JoinHostPort("localhost", listenPort)
	if !ProbeTCP(testCTX, target, module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	// Check the resulting metrics.
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	// Check values
	expectedResults := map[string]float64{
		"probe_ssl_earliest_cert_expiry":                float64(olderRootCertExpiry.Unix()),
		"probe_ssl_last_chain_expiry_timestamp_seconds": float64(serverCertExpiry.Unix()),
		"probe_ssl_last_chain_info":                     1,
		"probe_tls_version_info":                        1,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestTCPConnectionQueryResponseStartTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create test certificates valid for 1 day.
	certExpiry := time.Now().AddDate(0, 0, 1)
	testCertTmpl := generateCertificateTemplate(certExpiry, true)
	testCertTmpl.IsCA = true
	_, testCertPem, testKey := generateSelfSignedCertificate(testCertTmpl)

	// CAFile must be passed via filesystem, use a tempfile.
	tmpCaFile, err := os.CreateTemp("", "cafile.pem")
	if err != nil {
		t.Fatalf("Error creating CA tempfile: %s", err)
	}
	if _, err := tmpCaFile.Write(testCertPem); err != nil {
		t.Fatalf("Error writing CA tempfile: %s", err)
	}
	if err := tmpCaFile.Close(); err != nil {
		t.Fatalf("Error closing CA tempfile: %s", err)
	}
	defer os.Remove(tmpCaFile.Name())

	// Define some (bogus) example SMTP dialog with STARTTLS.
	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocolFallback: true,
			QueryResponse: []config.QueryResponse{
				{Expect: config.MustNewRegexp("^220.*ESMTP.*$")},
				{Send: "EHLO tls.prober"},
				{Expect: config.MustNewRegexp("^250-STARTTLS")},
				{Send: "STARTTLS"},
				{Expect: config.MustNewRegexp("^220")},
				{StartTLS: true},
				{Send: "EHLO tls.prober"},
				{Expect: config.MustNewRegexp("^250-AUTH")},
				{Send: "QUIT"},
			},
			TLSConfig: pconfig.TLSConfig{
				CAFile:             tmpCaFile.Name(),
				InsecureSkipVerify: false,
			},
		},
	}

	// Handle server side of this test.
	ch := make(chan (struct{}))
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		defer conn.Close()
		fmt.Fprintf(conn, "220 ESMTP StartTLS pseudo-server\n")
		if _, e := fmt.Fscanf(conn, "EHLO tls.prober\n"); e != nil {
			panic("Error in dialog. No EHLO received.")
		}
		fmt.Fprintf(conn, "250-pseudo-server.example.net\n")
		fmt.Fprintf(conn, "250-STARTTLS\n")
		fmt.Fprintf(conn, "250 DSN\n")

		if _, e := fmt.Fscanf(conn, "STARTTLS\n"); e != nil {
			panic("Error in dialog. No (TLS) STARTTLS received.")
		}
		fmt.Fprintf(conn, "220 2.0.0 Ready to start TLS\n")

		testKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)})
		testcert, err := tls.X509KeyPair(testCertPem, testKeyPem)
		if err != nil {
			panic(fmt.Sprintf("Failed to decode TLS testing keypair: %s\n", err))
		}

		// Do the server-side upgrade to TLS.
		tlsConfig := &tls.Config{
			ServerName:   "localhost",
			Certificates: []tls.Certificate{testcert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		}
		tlsConn := tls.Server(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			panic(fmt.Sprintf("TLS Handshake (server) failed: %s\n", err))
		}
		defer tlsConn.Close()

		// Continue encrypted.
		if _, e := fmt.Fscanf(tlsConn, "EHLO"); e != nil {
			panic("Error in dialog. No (TLS) EHLO received.")
		}
		fmt.Fprintf(tlsConn, "250-AUTH\n")
		fmt.Fprintf(tlsConn, "250 DSN\n")
		ch <- struct{}{}
	}()

	// Do the client side of this test.
	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	// Check the probe_ssl_earliest_cert_expiry.
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_ssl_earliest_cert_expiry": float64(certExpiry.Unix()),
		"probe_tls_cipher_info":          1,
	}
	checkRegistryResults(expectedResults, mfs, t)

	expectedLabels := map[string]map[string]string{
		"probe_tls_cipher_info": {
			"cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
	}
	checkRegistryLabels(expectedLabels, mfs, t)
}

func TestTCPConnectionWithTLSAndCRL(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
	crlServer := newCRLServer(t, createCRL(t, ca, caKey, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour)))
	leaf, leafKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 1000, CRLURL: crlServer.URL}, ca, caKey)

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch := make(chan struct{})
	logger := promslog.NewNopLogger()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert(leafKey, leaf, ca)},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		})
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			logger.Error("Error TLS Handshake (server) failed", "err", err)
		} else {
			fmt.Fprintf(tlsConn, "Hello World!\n")
		}
		ch <- struct{}{}
	}()

	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			TLS:                true,
			TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
			CheckRevoked:       true,
		},
	}

	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, logger) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", map[string]string{"subject": "CN=Test Leaf,O=Example Org"}); !ok || val != 1 {
		t.Errorf("Expected probe_ssl_crl_available=1, got %v (found=%v)", val, ok)
	}
}

func TestTCPConnectionQueryResponseStartTLSAndCRL(t *testing.T) {
	ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
	crlServer := newCRLServer(t, createCRL(t, ca, caKey, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour)))
	leaf, leafKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 1100, CRLURL: crlServer.URL}, ca, caKey)

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocolFallback: true,
			QueryResponse: []config.QueryResponse{
				{Expect: config.MustNewRegexp("^220.*ESMTP.*$")},
				{Send: "STARTTLS"},
				{Expect: config.MustNewRegexp("^220")},
				{StartTLS: true},
			},
			TLSConfig:    pconfig.TLSConfig{InsecureSkipVerify: true},
			CheckRevoked: true,
		},
	}

	ch := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(conn, "220 ESMTP StartTLS pseudo-server\n")
		if _, e := fmt.Fscanf(conn, "STARTTLS\n"); e != nil {
			panic("Error in dialog. No STARTTLS received.")
		}
		fmt.Fprintf(conn, "220 2.0.0 Ready to start TLS\n")

		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert(leafKey, leaf, ca)},
		})
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			panic(fmt.Sprintf("TLS Handshake (server) failed: %s\n", err))
		}
		ch <- struct{}{}
	}()

	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", map[string]string{"subject": "CN=Test Leaf,O=Example Org"}); !ok || val != 1 {
		t.Errorf("Expected probe_ssl_crl_available=1 after StartTLS, got %v (found=%v)", val, ok)
	}
}

func TestTCPConnectionQueryResponseIRC(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocolFallback: true,
			QueryResponse: []config.QueryResponse{
				{Send: "NICK prober"},
				{Send: "USER prober prober prober :prober"},
				{Expect: config.MustNewRegexp("^:[^ ]+ 001")},
			},
		},
	}

	ch := make(chan (struct{}))
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		fmt.Fprintf(conn, ":ircd.localhost NOTICE AUTH :*** Looking up your hostname...\n")
		var nick, user, mode, unused, realname string
		fmt.Fscanf(conn, "NICK %s", &nick)
		fmt.Fscanf(conn, "USER %s %s %s :%s", &user, &mode, &unused, &realname)
		fmt.Fprintf(conn, ":ircd.localhost 001 %s :Welcome to IRC!\n", nick)
		conn.Close()
		ch <- struct{}{}
	}()
	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		fmt.Fprintf(conn, ":ircd.localhost NOTICE AUTH :*** Looking up your hostname...\n")
		var nick, user, mode, unused, realname string
		fmt.Fscanf(conn, "NICK %s", &nick)
		fmt.Fscanf(conn, "USER %s %s %s :%s", &user, &mode, &unused, &realname)
		fmt.Fprintf(conn, "ERROR: Your IP address has been blacklisted.\n")
		conn.Close()
		ch <- struct{}{}
	}()
	registry = prometheus.NewRegistry()
	if ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module succeeded, expected failure.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_failed_due_to_regex": 1,
	}
	checkRegistryResults(expectedResults, mfs, t)
	<-ch
}

func TestTCPConnectionQueryResponseMatching(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	time.Sleep(time.Millisecond * 100)
	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocolFallback: true,
			QueryResponse: []config.QueryResponse{
				{
					Expect: config.MustNewRegexp("^SSH-2.0-([^ -]+)(?: (.*))?$"),
					Send:   "CONFIRM ${1}",
					Labels: []config.Label{
						{
							Name:  "ssh_version",
							Value: "${1}",
						},
						{
							Name:  "ssh_comments",
							Value: "${2}",
						},
					},
				},
			},
		},
	}

	ch := make(chan string)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		fmt.Fprintf(conn, "SSH-2.0-OpenSSH_6.9p1 Debian-2\n")
		var version string
		fmt.Fscanf(conn, "CONFIRM %s", &version)
		conn.Close()
		ch <- version
	}()
	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	if got, want := <-ch, "OpenSSH_6.9p1"; got != want {
		t.Fatalf("Read unexpected version: got %q, want %q", got, want)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_failed_due_to_regex": 0,
	}
	checkRegistryResults(expectedResults, mfs, t)
	// Check labels
	expectedLabels := map[string]map[string]string{
		"probe_expect_info": {
			"ssh_version":  "OpenSSH_6.9p1",
			"ssh_comments": "Debian-2",
		},
	}
	checkRegistryLabels(expectedLabels, mfs, t)

}

func TestTCPConnectionQueryResponseByteMode(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocolFallback: true,
			QueryResponse: []config.QueryResponse{
				{
					ExpectBytes: "not-a-line",
				},
			},
		},
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		conn.Write([]byte("not-a-line"))
		conn.Close()
	}()
	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_failed_due_to_regex": 0,
		"probe_failed_due_to_bytes": 0,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestTCPConnectionQueryResponseByteModeFail(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocolFallback: true,
			QueryResponse: []config.QueryResponse{
				{
					ExpectBytes: "not-a-line",
				},
			},
		},
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		conn.Write([]byte("something-else"))
		conn.Close()
	}()
	registry := prometheus.NewRegistry()
	if ProbeTCP(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module succeeded, expected failure.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_failed_due_to_regex": 0,
		"probe_failed_due_to_bytes": 1,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestTCPConnectionProtocol(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	// This test assumes that listening TCP listens both IPv6 and IPv4 traffic and
	// localhost resolves to both 127.0.0.1 and ::1. we must skip the test if either
	// of these isn't true. This should be true for modern Linux systems.
	if runtime.GOOS == "dragonfly" || runtime.GOOS == "openbsd" {
		t.Skip("IPv6 socket isn't able to accept IPv4 traffic in the system.")
	}
	_, err := net.ResolveIPAddr("ip6", "localhost")
	if err != nil {
		t.Skip("\"localhost\" doesn't resolve to ::1.")
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Prefer IPv4
	module := config.Module{
		TCP: config.TCPProbe{
			IPProtocol: "ip4",
		},
	}

	registry := prometheus.NewRegistry()
	result := ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
	if !result {
		t.Fatalf("TCP protocol: \"tcp\", prefer: \"ip4\" connection test failed, expected success.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_ip_protocol": 4,
	}
	checkRegistryResults(expectedResults, mfs, t)

	// Prefer IPv6
	module = config.Module{
		TCP: config.TCPProbe{
			IPProtocol: "ip6",
		},
	}

	registry = prometheus.NewRegistry()
	result = ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
	if !result {
		t.Fatalf("TCP protocol: \"tcp\", prefer: \"ip6\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults = map[string]float64{
		"probe_ip_protocol": 6,
	}
	checkRegistryResults(expectedResults, mfs, t)

	// Prefer nothing
	module = config.Module{
		TCP: config.TCPProbe{},
	}

	registry = prometheus.NewRegistry()
	result = ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
	if !result {
		t.Fatalf("TCP protocol: \"tcp\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults = map[string]float64{
		"probe_ip_protocol": 6,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestPrometheusTimeoutTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	ch := make(chan (struct{}))
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		conn.Close()
		ch <- struct{}{}
	}()
	testCTX, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	if ProbeTCP(testCTX, ln.Addr().String(), config.Module{TCP: config.TCPProbe{
		IPProtocolFallback: true,
		QueryResponse: []config.QueryResponse{
			{
				Expect: config.MustNewRegexp("SSH-2.0-(OpenSSH_6.9p1) Debian-2"),
			},
		},
	}}, registry, promslog.NewNopLogger()) {
		t.Fatalf("TCP module succeeded, expected timeout failure.")
	}
	<-ch
}

func TestProbeExpectInfo(t *testing.T) {
	registry := prometheus.NewRegistry()
	qr := config.QueryResponse{
		Expect: config.MustNewRegexp("^SSH-2.0-([^ -]+)(?: (.*))?$"),
		Labels: []config.Label{
			{
				Name:  "label1",
				Value: "got ${1} here",
			},
			{
				Name:  "label2",
				Value: "${1} on ${2}",
			},
		},
	}
	bytes := []byte("SSH-2.0-OpenSSH_6.9p1 Debian-2")
	match := qr.Expect.FindSubmatchIndex(bytes)

	probeExpectInfo(registry, &qr, bytes, match)

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	// Check labels
	expectedLabels := map[string]map[string]string{
		"probe_expect_info": {
			"label1": "got OpenSSH_6.9p1 here",
			"label2": "OpenSSH_6.9p1 on Debian-2",
		},
	}
	checkRegistryLabels(expectedLabels, mfs, t)

}
