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

func TestHTTP(t *testing.T) {
	runCases(t, []probeCase{
		{
			prober:  "http",
			name:    "default prefers ipv6",
			target:  "http://testserver:30080",
			want:    1,
			metrics: []metricWant{{name: "probe_ip_protocol", value: 6}},
		},
		{
			prober: "http",
			name:   "default falls back to ipv4",
			// testserver-v4 has an A record only, on the IPv4-only network.
			target:  "http://testserver-v4:30080",
			want:    1,
			metrics: []metricWant{{name: "probe_ip_protocol", value: 4}},
		},
	})
}
