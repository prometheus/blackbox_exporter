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

const (
	httpOK = "http://badserver:30080"
	// badserver-v4 has an A record only, on the IPv4-only network.
	httpIPv4Only = "http://badserver-v4:30080"
)

var httpCases = []probeCase{
	{prober: "http", name: "default prefers ipv6", target: httpOK, want: 1, metrics: usedIP(6)},
	{prober: "http", name: "default falls back to ipv4", target: httpIPv4Only, want: 1, metrics: usedIP(4)},
}

func TestHTTP(t *testing.T) { runCases(t, httpCases) }
