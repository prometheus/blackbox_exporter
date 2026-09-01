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
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

func gatherICMPDurationPhases(t *testing.T, registry *prometheus.Registry) map[string]float64 {
	t.Helper()
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	phases := make(map[string]float64)
	for _, mf := range mfs {
		if mf.GetName() != "probe_icmp_duration_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			phase := ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "phase" {
					phase = l.GetValue()
				}
			}
			if phase != "" {
				phases[phase] = m.GetGauge().GetValue()
			}
		}
	}
	return phases
}

// TestProbeICMPDurationRTTOmittedOnFailure ensures failed probes do not export
// probe_icmp_duration_seconds{phase="rtt"} as 0, which pollutes aggregations.
// See https://github.com/prometheus/blackbox_exporter/issues/984
func TestProbeICMPDurationRTTOmittedOnFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network dependent test")
	}
	// TEST-NET-1 is non-routable; echo requests should time out.
	target := "192.0.2.1"
	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	success := ProbeICMP(ctx, target, config.Module{
		Timeout: 500 * time.Millisecond,
		ICMP:    config.ICMPProbe{IPProtocol: "ip4", IPProtocolFallback: false},
	}, registry, promslog.NewNopLogger())
	if success {
		t.Fatal("expected ICMP probe to fail against non-routable TEST-NET-1 address")
	}

	phases := gatherICMPDurationPhases(t, registry)
	if _, ok := phases["rtt"]; ok {
		t.Fatalf("expected phase=rtt to be omitted on failure, got phases %v", phases)
	}
	// resolve/setup should still be present (pre-created labels).
	if _, ok := phases["resolve"]; !ok {
		t.Fatalf("expected phase=resolve to be present, got phases %v", phases)
	}
}

// TestProbeICMPDurationRTTPresentOnSuccess verifies rtt is exported when a reply is received.
func TestProbeICMPDurationRTTPresentOnSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network dependent test")
	}
	// Unprivileged ICMP is only attempted on darwin/linux.
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ICMP probe success path requires darwin or linux")
	}

	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	success := ProbeICMP(ctx, "127.0.0.1", config.Module{
		Timeout: 3 * time.Second,
		ICMP:    config.ICMPProbe{IPProtocol: "ip4", IPProtocolFallback: false},
	}, registry, promslog.NewNopLogger())
	if !success {
		t.Skip("ICMP to 127.0.0.1 failed (permissions or local firewall); cannot assert success-path rtt metric")
	}

	phases := gatherICMPDurationPhases(t, registry)
	if _, ok := phases["rtt"]; !ok {
		t.Fatalf("expected phase=rtt on success, got phases %v", phases)
	}
	if phases["rtt"] <= 0 {
		t.Fatalf("expected positive rtt on success, got %v", phases["rtt"])
	}
}
