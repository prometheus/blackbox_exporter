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
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/prometheus/blackbox_exporter/config"
)

// startUnaryTestServer serves the standard health service, with or without the
// reflection service next to it, and returns its address.
func startUnaryTestServer(t *testing.T, withReflection bool) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	s := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("service", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("down", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpc_health_v1.RegisterHealthServer(s, healthServer)
	if withReflection {
		reflection.Register(s)
	}
	go s.Serve(ln)
	t.Cleanup(s.Stop)
	return ln.Addr().String()
}

func runUnaryProbe(t *testing.T, addr string, probe config.GRPCProbe) (unaryResult, error) {
	t.Helper()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return probeUnaryMethod(ctx, conn, probe, promslog.NewNopLogger())
}

func TestGRPCUnaryMethod(t *testing.T) {
	addr := startUnaryTestServer(t, true)

	tests := []struct {
		name        string
		probe       config.GRPCProbe
		wantErr     string
		wantCode    codes.Code
		wantMatched *bool
	}{
		{
			name:  "call without an expectation",
			probe: config.GRPCProbe{Method: "grpc.health.v1.Health/Check", Request: `service: "service"`},
		},
		{
			name:  "leading slash in the method",
			probe: config.GRPCProbe{Method: "/grpc.health.v1.Health/Check", Request: `service: "service"`},
		},
		{
			name: "response matches",
			probe: config.GRPCProbe{
				Method:           "grpc.health.v1.Health/Check",
				Request:          `service: "service"`,
				ExpectedResponse: `status: SERVING`,
			},
			wantMatched: new(true),
		},
		{
			name: "response differs",
			probe: config.GRPCProbe{
				Method:           "grpc.health.v1.Health/Check",
				Request:          `service: "down"`,
				ExpectedResponse: `status: SERVING`,
			},
			wantErr:     "does not match expected_response",
			wantMatched: new(false),
		},
		{
			name:     "server returns an error status",
			probe:    config.GRPCProbe{Method: "grpc.health.v1.Health/Check", Request: `service: "missing"`},
			wantErr:  "NotFound",
			wantCode: codes.NotFound,
		},
		{
			name:     "unknown service",
			probe:    config.GRPCProbe{Method: "does.not.Exist/Check"},
			wantErr:  "reflection lookup",
			wantCode: codes.NotFound,
		},
		{
			name:    "unknown method",
			probe:   config.GRPCProbe{Method: "grpc.health.v1.Health/Missing"},
			wantErr: "has no method Missing",
		},
		{
			name:    "streaming method",
			probe:   config.GRPCProbe{Method: "grpc.health.v1.Health/Watch", Request: `service: "service"`},
			wantErr: "streaming method",
		},
		{
			name:    "request with an unknown field",
			probe:   config.GRPCProbe{Method: "grpc.health.v1.Health/Check", Request: `nope: 1`},
			wantErr: "cannot parse request as grpc.health.v1.HealthCheckRequest",
		},
		{
			name: "expected response with an unknown field",
			probe: config.GRPCProbe{
				Method:           "grpc.health.v1.Health/Check",
				Request:          `service: "service"`,
				ExpectedResponse: `nope: 1`,
			},
			wantErr: "cannot parse expected_response as grpc.health.v1.HealthCheckResponse",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := runUnaryProbe(t, addr, tc.probe)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("expected an error containing %q, got %v", tc.wantErr, err)
			}
			if res.statusCode != tc.wantCode {
				t.Errorf("expected status code %s, got %s", tc.wantCode, res.statusCode)
			}
			switch {
			case tc.wantMatched == nil && res.matched != nil:
				t.Errorf("expected no match result, got %v", *res.matched)
			case tc.wantMatched != nil && (res.matched == nil || *res.matched != *tc.wantMatched):
				t.Errorf("expected match result %v, got %v", *tc.wantMatched, res.matched)
			}
		})
	}
}

func TestGRPCUnaryMethodWithoutReflection(t *testing.T) {
	addr := startUnaryTestServer(t, false)

	res, err := runUnaryProbe(t, addr, config.GRPCProbe{Method: "grpc.health.v1.Health/Check", Request: `service: "service"`})
	if err == nil || !strings.Contains(err.Error(), "reflection lookup") {
		t.Fatalf("expected a reflection error, got %v", err)
	}
	if res.statusCode != codes.Unimplemented {
		t.Errorf("expected status code %s, got %s", codes.Unimplemented, res.statusCode)
	}
}

func TestProbeGRPCUnaryMethod(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	addr := startUnaryTestServer(t, true)

	tests := []struct {
		name     string
		expected string
		success  bool
		match    float64
	}{
		{name: "matching response", expected: `status: SERVING`, success: true, match: 1},
		{name: "different response", expected: `status: NOT_SERVING`, success: false, match: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			registry := prometheus.NewRegistry()

			result := ProbeGRPC(ctx, addr, config.Module{
				Timeout: time.Second,
				GRPC: config.GRPCProbe{
					PreferredIPProtocol: "ip4",
					IPProtocolFallback:  true,
					Method:              "grpc.health.v1.Health/Check",
					Request:             `service: "service"`,
					ExpectedResponse:    tc.expected,
				},
			}, registry, promslog.NewNopLogger())
			if result != tc.success {
				t.Fatalf("expected probe success %v, got %v", tc.success, result)
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			for _, mf := range mfs {
				if mf.GetName() == "probe_grpc_healthcheck_response" {
					t.Fatal("health check metrics must not be exposed for a unary method")
				}
			}
			checkRegistryResults(map[string]float64{
				"probe_grpc_ssl":            0,
				"probe_grpc_status_code":    0,
				"probe_grpc_response_match": tc.match,
			}, mfs, t)
			checkMetrics(map[string]map[string]map[string]struct{}{
				"probe_grpc_duration_seconds": {"phase": {"resolve": {}, "reflection": {}, "check": {}}},
			}, mfs, t)
		})
	}
}
