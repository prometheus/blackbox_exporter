// Copyright The Prometheus Authors
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
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestUnixConnection(t *testing.T) {
	// Create a temporary file for the socket.
	tmpfile, err := os.CreateTemp("", "unix-socket-test")
	if err != nil {
		t.Fatalf("Error creating temp file: %s", err)
	}
	socketPath := tmpfile.Name()
	// Close and remove the file so we can use the path for the socket.
	tmpfile.Close()
	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
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
	if !ProbeUnix(testCTX, ln.Addr().String(), config.Module{Unix: config.UnixProbe{}}, registry, promslog.NewNopLogger()) {
		t.Fatalf("Unix module failed, expected success.")
	}
	<-ch
}

func TestUnixConnectionWithTLSAndCRL(t *testing.T) {
	ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
	crlServer := newCRLServer(t, createCRL(t, ca, caKey, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour)))
	leaf, leafKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 1200, CRLURL: crlServer.URL}, ca, caKey)

	tmpfile, err := os.CreateTemp("", "unix-socket-tls-test")
	if err != nil {
		t.Fatalf("Error creating temp file: %s", err)
	}
	socketPath := tmpfile.Name()
	tmpfile.Close()
	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	ch := make(chan struct{})
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
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		})
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err == nil {
			fmt.Fprintf(tlsConn, "Hello World!\n")
		}
		ch <- struct{}{}
	}()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	module := config.Module{
		Unix: config.UnixProbe{
			TLS:          true,
			TLSConfig:    pconfig.TLSConfig{InsecureSkipVerify: true},
			CheckRevoked: true,
		},
	}

	registry := prometheus.NewRegistry()
	if !ProbeUnix(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger()) {
		t.Fatalf("Unix module failed, expected success.")
	}
	<-ch

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", map[string]string{"subject": "CN=Test Leaf,O=Example Org"}); !ok || val != 1 {
		t.Errorf("Expected probe_ssl_crl_available=1, got %v (found=%v)", val, ok)
	}

	expectedResults := map[string]float64{
		"probe_tls_cipher_info": 1,
	}
	checkRegistryResults(expectedResults, mfs, t)

	expectedLabels := map[string]map[string]string{
		"probe_tls_cipher_info": {
			"cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
	}
	checkRegistryLabels(expectedLabels, mfs, t)
}

func TestUnixConnectionFails(t *testing.T) {
	// Non-existent socket.
	socketPath := "/tmp/non-existent-socket-for-blackbox-exporter-test"
	os.Remove(socketPath) // Ensure it doesn't exist

	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ProbeUnix(testCTX, socketPath, config.Module{Unix: config.UnixProbe{}}, registry, promslog.NewNopLogger()) {
		t.Fatalf("Unix module succeeded, expected failure.")
	}
}
