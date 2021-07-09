// Copyright 2016 The Prometheus Authors
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
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func TestProbeICMP(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; not enough privileges to set up ICMP test")
	}

	timeout := 2000 * time.Millisecond
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(timeout))
	defer cancel()

	registry := prometheus.NewRegistry()
	logbuf := &bytes.Buffer{}

	success := ProbeICMP(
		ctx,
		"127.0.0.1",
		config.Module{
			Prober:  "icmp",
			Timeout: timeout,
			ICMP: config.ICMPProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: false,
				PayloadSize:        64,
			},
		},
		registry,
		log.NewLogfmtLogger(logbuf),
	)

	if success != true {
		t.Fatalf("ProbeICMP failed unexpectedly:\n\n%s", logbuf.String())
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("unexpected error gathering metrics: %s", err.Error())
	}

	checkRegistryMetrics(t, mfs,
		map[string][]map[string]string{
			"probe_dns_lookup_time_seconds": nil,
			"probe_icmp_duration_seconds": {
				{"phase": "resolve"},
				{"phase": "rtt"},
				{"phase": "setup"},
			},
			"probe_icmp_reply_hop_limit": nil,
			"probe_ip_addr_hash":         nil,
			"probe_ip_protocol":          nil,
		})
}
