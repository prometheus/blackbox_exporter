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

//go:build e2e

package e2e

import "testing"

func TestICMP(t *testing.T) {
	runCases(t, []probeCase{
		{
			prober:  "icmp",
			name:    "ipv4",
			target:  "testserver",
			module:  `{preferred_ip_protocol: ip4}`,
			want:    1,
			metrics: []metricWant{{name: "probe_ip_protocol", value: 4}},
		},
		// The nobody user has no raw socket permission, so these pass only if the prober uses unprivileged ICMP sockets.
		{
			prober:     "icmp",
			name:       "ipv4 as nobody",
			exporter:   "nobody",
			dockerArgs: []string{"--user", "nobody"},
			target:     "testserver",
			module:     `{preferred_ip_protocol: ip4}`,
			want:       1,
			metrics:    []metricWant{{name: "probe_ip_protocol", value: 4}},
		},
		{
			prober:     "icmp",
			name:       "ipv6 as nobody",
			exporter:   "nobody",
			dockerArgs: []string{"--user", "nobody"},
			target:     "testserver",
			module:     `{preferred_ip_protocol: ip6, ip_protocol_fallback: false}`,
			want:       1,
			metrics:    []metricWant{{name: "probe_ip_protocol", value: 6}},
		},
		// Turning off unprivileged ICMP sockets makes the prober fall back to raw sockets.
		{
			prober:     "icmp",
			name:       "ipv4 privileged",
			exporter:   "icmp_privileged",
			dockerArgs: []string{"--sysctl", "net.ipv4.ping_group_range=1 0"},
			target:     "testserver",
			module:     `{preferred_ip_protocol: ip4}`,
			want:       1,
			wantLog:    "will attempt privileged",
			metrics:    []metricWant{{name: "probe_ip_protocol", value: 4}},
		},
		{
			prober:     "icmp",
			name:       "ipv6 privileged",
			exporter:   "icmp_privileged",
			dockerArgs: []string{"--sysctl", "net.ipv4.ping_group_range=1 0"},
			target:     "testserver",
			module:     `{preferred_ip_protocol: ip6, ip_protocol_fallback: false}`,
			want:       1,
			wantLog:    "will attempt privileged",
			metrics:    []metricWant{{name: "probe_ip_protocol", value: 6}},
		},
		{
			prober:  "icmp",
			name:    "dont fragment",
			target:  "testserver",
			module:  `{preferred_ip_protocol: ip4, dont_fragment: true}`,
			want:    1,
			metrics: []metricWant{{name: "probe_ip_protocol", value: 4}},
		},
		{
			prober:     "icmp",
			name:       "raw socket as nobody",
			exporter:   "nobody",
			dockerArgs: []string{"--user", "nobody"},
			target:     "testserver",
			module:     `{preferred_ip_protocol: ip4, dont_fragment: true}`,
			want:       0,
			wantLog:    "operation not permitted",
		},
		// dont_fragment uses a raw socket, which does not fragment, so a packet over the MTU fails to send.
		{
			prober:  "icmp",
			name:    "raw socket over mtu",
			target:  "testserver",
			module:  `{preferred_ip_protocol: ip4, dont_fragment: true, payload_size: 1500}`,
			want:    0,
			wantLog: "message too long",
		},
	})
}
