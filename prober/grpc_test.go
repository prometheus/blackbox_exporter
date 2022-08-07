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
	"google.golang.org/grpc/metadata"
	"net"
	"os"
	"testing"
	"time"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestGRPCConnection(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
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

	result := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
		},
		}, registry, promslog.NewNopLogger())

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

func TestGRPCConnectionWithMetadata(t *testing.T) {

	const binaryMetadataValue = "\u0080"

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Error retrieving port for socket: %s", err)
	}

	metadataUnaryInterceptor := func(ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		h, err := handler(ctx, req)
		md, _ := metadata.FromIncomingContext(ctx)

		if md.Get("key1")[0] != "value1" || md.Get("key1")[1] != "value2" {
			t.Fatalf("Metadata key or value mismatch (key 'key1', value ['%s','%s']. Expected value: ['value1','value2'])", md.Get("key1")[0], md.Get("key1")[1])
		}
		if md.Get("key2-bin")[0] != binaryMetadataValue {
			t.Fatalf("Metadata key or value mismatch (key 'key2-bin', value '%s'. Expected value: '%s')", binaryMetadataValue, md.Get("key2-bin")[0])
		}

		return h, err
	}

	serverInterceptor := grpc.UnaryInterceptor(metadataUnaryInterceptor)

	s := grpc.NewServer(serverInterceptor)
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

	result := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Metadata: metadata.Pairs("key1", "value1",
				"key1", "value2",
				"key2-bin", binaryMetadataValue,
			),
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
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
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

	resultService1 := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "service1",
		},
		}, registryService1, promslog.NewNopLogger())

	if !resultService1 {
		t.Fatalf("GRPC probe failed for service1")
	}

	registryService2 := prometheus.NewRegistry()
	resultService2 := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "service2",
		},
		}, registryService2, promslog.NewNopLogger())

	if resultService2 {
		t.Fatalf("GRPC probe succeed for service2")
	}

	registryService3 := prometheus.NewRegistry()
	resultService3 := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "service3",
		},
		}, registryService3, promslog.NewNopLogger())

	if resultService3 {
		t.Fatalf("GRPC probe succeed for service3")
	}
}

func TestGRPCTLSConnection(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

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

	result := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			TLS:                true,
			TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
			IPProtocolFallback: false,
		},
		}, registry, promslog.NewNopLogger())

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
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
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

	result := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			TLS:                true,
			TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
			IPProtocolFallback: false,
		},
		}, registry, promslog.NewNopLogger())

	if result {
		t.Fatalf("GRPC probe succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := map[string]float64{
		"probe_grpc_ssl":         0,
		"probe_grpc_status_code": 14, // UNAVAILABLE
	}

	checkRegistryResults(expectedResults, mfs, t)

}

func TestGRPCServiceNotFound(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
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

	result := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "NonExistingService",
		},
		}, registry, promslog.NewNopLogger())

	if result {
		t.Fatalf("GRPC probe succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := map[string]float64{
		"probe_grpc_ssl":         0,
		"probe_grpc_status_code": 5, // NOT_FOUND
	}

	checkRegistryResults(expectedResults, mfs, t)
}

func TestGRPCHealthCheckUnimplemented(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
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

	result := ProbeGRPC(testCTX, "localhost:"+port,
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "NonExistingService",
		},
		}, registry, promslog.NewNopLogger())

	if result {
		t.Fatalf("GRPC probe succeed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := map[string]float64{
		"probe_grpc_ssl":         0,
		"probe_grpc_status_code": 12, // UNIMPLEMENTED
	}

	checkRegistryResults(expectedResults, mfs, t)
}

func TestGRPCAbsentFailedTLS(t *testing.T) {
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()

	// probe and invalid port to trigger TCP/TLS error
	result := ProbeGRPC(testCTX, "localhost:0",
		config.Module{Timeout: time.Second, GRPC: config.GRPCProbe{
			IPProtocolFallback: false,
			Service:            "NonExistingService",
		},
		}, registry, promslog.NewNopLogger())

	if result {
		t.Fatalf("GRPC probe succeeded, should have failed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	absentMetrics := []string{
		"probe_ssl_earliest_cert_expiry",
		"probe_tls_version_info",
		"probe_ssl_last_chain_info",
	}

	checkAbsentMetrics(absentMetrics, mfs, t)
}
