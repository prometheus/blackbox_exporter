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

func TestGRPC(t *testing.T) {
	runCases(t, []probeCase{
		{
			prober: "grpc",
			name:   "ipv6 only listener",
			// testserver has A and AAAA records, but this port listens on its IPv6 address only.
			target:  "testserver:30051",
			module:  `{preferred_ip_protocol: ip6, ip_protocol_fallback: false}`,
			want:    1,
			metrics: []metricWant{{name: "probe_ip_protocol", value: 6}},
		},
	})
}
