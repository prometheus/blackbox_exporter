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
	}
	checkRegistryLabels(expectedLabels, mfs, t)

	// Check values
	expectedResults := map[string]float64{
		"probe_ssl_earliest_cert_expiry": float64(certExpiry.Unix()),
		"probe_ssl_last_chain_info":      1,
		"probe_tls_version_info":         1,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestTCPConnectionWithTLSAndVerifiedCertificateChain(t *testing.T) {
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
	}
	checkRegistryResults(expectedResults, mfs, t)
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

func TestTCPConnectionProtocol(t *testing.T) {
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
	match := qr.Expect.Regexp.FindSubmatchIndex(bytes)

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
