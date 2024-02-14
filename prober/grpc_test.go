// Copyright 2021 The Prometheus Authors
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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestGRPCConnection(t *testing.T) {

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Error retrieving port for socket: %s", err)
	}
	s := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("service", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(s, healthServer)

	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("failed to serve: %v", err)
			return
		}
	}()
	defer s.GracefulStop()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()

	result := ProbeGRPC(testCTX, "localhost:"+port, url.Values{},
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
		},
		}, registry, log.NewNopLogger())

	if !result {
		t.Fatalf("GRPC probe failed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedMetrics := map[string]map[string]map[string]struct{}{
		"probe_grpc_healthcheck_response": {
			"serving_status": {
				"UNKNOWN":         {},
				"SERVING":         {},
				"NOT_SERVING":     {},
				"SERVICE_UNKNOWN": {},
			},
		},
	}

	checkMetrics(expectedMetrics, mfs, t)

	expectedResults := map[string]float64{
		"probe_grpc_ssl":         0,
		"probe_grpc_status_code": 0,
	}

	checkRegistryResults(expectedResults, mfs, t)
}

func TestMultipleGRPCservices(t *testing.T) {

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Error retrieving port for socket: %s", err)
	}
	s := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("service1", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("service2", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpc_health_v1.RegisterHealthServer(s, healthServer)

	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("failed to serve: %v", err)
			return
		}
	}()
	defer s.GracefulStop()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registryService1 := prometheus.NewRegistry()

	resultService1 := ProbeGRPC(testCTX, "localhost:"+port, url.Values{},
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "service1",
		},
		}, registryService1, log.NewNopLogger())

	if !resultService1 {
		t.Fatalf("GRPC probe failed for service1")
	}

	registryService2 := prometheus.NewRegistry()
	resultService2 := ProbeGRPC(testCTX, "localhost:"+port, url.Values{},
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "service2",
		},
		}, registryService2, log.NewNopLogger())

	if resultService2 {
		t.Fatalf("GRPC probe succeed for service2")
	}

	registryService3 := prometheus.NewRegistry()
	resultService3 := ProbeGRPC(testCTX, "localhost:"+port, url.Values{},
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "service3",
		},
		}, registryService3, log.NewNopLogger())

	if resultService3 {
		t.Fatalf("GRPC probe succeed for service3")
	}
}

func TestGRPCTLSConnection(t *testing.T) {

	certExpiry := time.Now().AddDate(0, 0, 1)
	testCertTmpl := generateCertificateTemplate(certExpiry, false)
	testCertTmpl.IsCA = true
	_, testcertPem, testKey := generateSelfSignedCertificate(testCertTmpl)

	// CAFile must be passed via filesystem, use a tempfile.
	tmpCaFile, err := os.CreateTemp("", "cafile.pem")
	if err != nil {
		t.Fatalf("Error creating CA tempfile: %s", err)
	}
	if _, err = tmpCaFile.Write(testcertPem); err != nil {
		t.Fatalf("Error writing CA tempfile: %s", err)
	}
	if err = tmpCaFile.Close(); err != nil {
		t.Fatalf("Error closing CA tempfile: %s", err)
	}
	defer os.Remove(tmpCaFile.Name())

	testKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)})
	testcert, err := tls.X509KeyPair(testcertPem, testKeyPem)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode TLS testing keypair: %s\n", err))
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{testcert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Error retrieving port for socket: %s", err)
	}

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	healthServer := health.NewServer()
	healthServer.SetServingStatus("service", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(s, healthServer)

	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("failed to serve: %v", err)
			return
		}
	}()
	defer s.GracefulStop()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()

	result := ProbeGRPC(testCTX, "localhost:"+port, url.Values{},
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			TLS:                true,
			TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
			IPProtocolFallback: false,
		},
		}, registry, log.NewNopLogger())

	if !result {
		t.Fatalf("GRPC probe failed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedLabels := map[string]map[string]string{
		"probe_tls_version_info": {
			"version": "TLS 1.2",
		},
	}
	checkRegistryLabels(expectedLabels, mfs, t)

	expectedResults := map[string]float64{
		"probe_grpc_ssl":         1,
		"probe_grpc_status_code": 0,
	}

	checkRegistryResults(expectedResults, mfs, t)
}

func TestNoTLSConnection(t *testing.T) {

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Error retrieving port for socket: %s", err)
	}
	s := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("service", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(s, healthServer)

	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("failed to serve: %v", err)
			return
		}
	}()
	defer s.GracefulStop()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()

	result := ProbeGRPC(testCTX, "localhost:"+port, url.Values{},
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			TLS:                true,
			TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
			IPProtocolFallback: false,
		},
		}, registry, log.NewNopLogger())

	if result {
		t.Fatalf("GRPC probe succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := map[string]float64{
		"probe_grpc_ssl":         0,
		"probe_grpc_status_code": 14, //UNAVAILABLE
	}

	checkRegistryResults(expectedResults, mfs, t)

}

func TestGRPCServiceNotFound(t *testing.T) {

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Error retrieving port for socket: %s", err)
	}
	s := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("service", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(s, healthServer)

	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("failed to serve: %v", err)
			return
		}
	}()
	defer s.GracefulStop()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()

	result := ProbeGRPC(testCTX, "localhost:"+port, url.Values{},
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "NonExistingService",
		},
		}, registry, log.NewNopLogger())

	if result {
		t.Fatalf("GRPC probe succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := map[string]float64{
		"probe_grpc_ssl":         0,
		"probe_grpc_status_code": 5, //NOT_FOUND
	}

	checkRegistryResults(expectedResults, mfs, t)
}

func TestGRPCHealthCheckUnimplemented(t *testing.T) {

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Error retrieving port for socket: %s", err)
	}
	s := grpc.NewServer()

	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("failed to serve: %v", err)
			return
		}
	}()
	defer s.GracefulStop()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()

	result := ProbeGRPC(testCTX, "localhost:"+port, url.Values{},
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "NonExistingService",
		},
		}, registry, log.NewNopLogger())

	if result {
		t.Fatalf("GRPC probe succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := map[string]float64{
		"probe_grpc_ssl":         0,
		"probe_grpc_status_code": 12, //UNIMPLEMENTED
	}

	checkRegistryResults(expectedResults, mfs, t)
}
