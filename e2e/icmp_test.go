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

import (
	"net/http"
	"testing"
)

const (
	icmpHost      = "badserver"
	fellBackToRaw = "will attempt privileged"
)

var icmpCases = []probeCase{
	{prober: "icmp", name: "ipv4", target: icmpHost, want: 1, metrics: usedIP(4), module: `{preferred_ip_protocol: ip4}`},
	{prober: "icmp", name: "ipv6", target: icmpHost, want: 1, metrics: usedIP(6), module: `{` + ip6Only + `}`},
	// nobody cannot open raw sockets, so these prove the unprivileged sockets work.
	{
		prober: "icmp", name: "ipv4 as nobody", exporter: "nobody", target: icmpHost, want: 1, metrics: usedIP(4),
		module: `{preferred_ip_protocol: ip4}`,
	},
	{
		prober: "icmp", name: "ipv6 as nobody", exporter: "nobody", target: icmpHost, want: 1, metrics: usedIP(6),
		module: `{` + ip6Only + `}`,
	},
	{
		prober: "icmp", name: "ipv4 privileged", exporter: "icmp_privileged", target: icmpHost, want: 1, metrics: usedIP(4), wantLog: fellBackToRaw,
		module: `{preferred_ip_protocol: ip4}`,
	},
	{
		prober: "icmp", name: "ipv6 privileged", exporter: "icmp_privileged", target: icmpHost, want: 1, metrics: usedIP(6), wantLog: fellBackToRaw,
		module: `{` + ip6Only + `}`,
	},
	{prober: "icmp", name: "dont fragment", target: icmpHost, want: 1, metrics: usedIP(4), module: `{preferred_ip_protocol: ip4, dont_fragment: true}`},
	{
		prober: "icmp", name: "raw socket as nobody", exporter: "nobody", target: icmpHost, want: 0, wantLog: "operation not permitted",
		module: `{preferred_ip_protocol: ip4, dont_fragment: true}`,
	},
	// dont_fragment uses a raw socket, which does not fragment, so a packet over the MTU fails to send.
	{
		prober: "icmp", name: "raw socket over mtu", target: icmpHost, want: 0, wantLog: "message too long",
		module: `{preferred_ip_protocol: ip4, dont_fragment: true, payload_size: 1500}`,
	},
}

func TestICMP(t *testing.T) { runCases(t, icmpCases) }

// TestICMPDontFragmentBit checks the bit on the wire, because the kernel answers an echo request whatever its flags.
func TestICMPDontFragmentBit(t *testing.T) {
	// Linux sets DF on every echo request while path MTU discovery is on.
	base := "http://" + startExporter(t, "pmtu_off", []string{"--sysctl", "net.ipv4.ip_no_pmtu_disc=1"}, "--config.file=/config/blackbox.yml")
	waitStatus(t, httpClient, base+"/-/healthy", http.StatusOK)
	for _, c := range []struct {
		module string
		df     float64
	}{{"icmp_ipv4", 0}, {"icmp_dont_fragment", 1}} {
		wantSuccess(t, base, c.module, icmpHost, 1)
		// badserver returns 500 on /df unless the last echo request it saw had DF set.
		wantSuccess(t, base, "http_2xx", httpOK+"/df", c.df)
	}
}
