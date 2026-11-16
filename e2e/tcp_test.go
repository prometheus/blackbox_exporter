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

const tcpOpen = "badserver:30080"

var tcpCases = []probeCase{
	{prober: "tcp", name: "ipv6", target: tcpOpen, want: 1, metrics: usedIP(6), module: `{` + ip6Only + `}`},
	// Proves badserver's IPv6-only listener, which the grpc case relies on.
	{
		prober: "tcp", name: "ipv6 only port refuses ipv4", target: grpcIPv6Only, want: 0, wantLog: "connection refused",
		module: `{preferred_ip_protocol: ip4, ip_protocol_fallback: false}`,
	},
}

func TestTCP(t *testing.T) { runCases(t, tcpCases) }
