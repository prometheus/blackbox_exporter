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

package main

import (
	"net"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var PROTOCOLS = [...]string{"udp", "tcp"}

// startDNSServer starts a DNS server with a given handler function on a random port.
// Returns the Server object itself as well as the net.Addr corresponding to the server port.
func startDNSServer(protocol string, handler func(dns.ResponseWriter, *dns.Msg)) (*dns.Server, net.Addr) {
	h := dns.NewServeMux()
	h.HandleFunc(".", handler)
	server := &dns.Server{Addr: ":0", Net: protocol, Handler: h}
	go server.ListenAndServe()
	// Wait until PacketConn becomes available, but give up after 1 second.
	for i := 0; server.PacketConn == nil && i < 200; i++ {
		if protocol == "tcp" && server.Listener != nil {
			break
		}
		if protocol == "udp" && server.PacketConn != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if protocol == "tcp" {
		return server, server.Listener.Addr()
	}
	return server, server.PacketConn.LocalAddr()
}

func recursiveDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	answers := []string{
		"example.com. 3600 IN A 127.0.0.1",
		"example.com. 3600 IN A 127.0.0.2",
	}
	for _, rr := range answers {
		a, err := dns.NewRR(rr)
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, a)
	}
	if err := w.WriteMsg(m); err != nil {
		panic(err)
	}
}

func TestRecursiveDNSResponse(t *testing.T) {
	tests := []struct {
		Probe         DNSProbe
		ShouldSucceed bool
	}{
		{
			DNSProbe{
				QueryName: "example.com",
			}, true,
		},
		{
			DNSProbe{
				QueryName:   "example.com",
				ValidRcodes: []string{"SERVFAIL", "NXDOMAIN"},
			}, false,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				ValidateAnswer: DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*7200.*"},
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, true,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				ValidateAuthority: DNSRRValidator{
					FailIfMatchesRegexp: []string{".*7200.*"},
				},
			}, true,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				ValidateAdditional: DNSRRValidator{
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, false,
		},
	}
	expectedOutput := []string{
		"probe_dns_answer_rrs 2\n",
		"probe_dns_authority_rrs 0\n",
		"probe_dns_additional_rrs 0\n",
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, recursiveDNSHandler)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.Protocol = protocol
			recorder := httptest.NewRecorder()
			result, _ := probeDNS(addr.String(), recorder, Module{Timeout: time.Second, DNS: test.Probe})
			if result != test.ShouldSucceed {
				t.Fatalf("Test %d had unexpected result: %v", i, result)
			}
			body := recorder.Body.String()
			for _, line := range expectedOutput {
				if !strings.Contains(body, line) {
					t.Fatalf("Did not find expected output in test %d: %q", i, line)
				}
			}
		}
	}
}

func authoritativeDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	a, err := dns.NewRR("example.com. 3600 IN A 127.0.0.1")
	if err != nil {
		panic(err)
	}
	m.Answer = append(m.Answer, a)

	authority := []string{
		"example.com. 7200 IN NS ns1.isp.net.",
		"example.com. 7200 IN NS ns2.isp.net.",
	}
	for _, rr := range authority {
		a, err := dns.NewRR(rr)
		if err != nil {
			panic(err)
		}
		m.Ns = append(m.Ns, a)
	}

	additional := []string{
		"ns1.isp.net. 7200 IN A 127.0.0.1",
		"ns1.isp.net. 7200 IN AAAA ::1",
		"ns2.isp.net. 7200 IN A 127.0.0.2",
	}
	for _, rr := range additional {
		a, err := dns.NewRR(rr)
		if err != nil {
			panic(err)
		}
		m.Extra = append(m.Extra, a)
	}

	if err := w.WriteMsg(m); err != nil {
		panic(err)
	}
}

func TestAuthoritativeDNSResponse(t *testing.T) {
	tests := []struct {
		Probe         DNSProbe
		ShouldSucceed bool
	}{
		{
			DNSProbe{
				QueryName: "example.com",
			}, true,
		},
		{
			DNSProbe{
				QueryName:   "example.com",
				ValidRcodes: []string{"SERVFAIL", "NXDOMAIN"},
			}, false,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				ValidateAnswer: DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*3600.*"},
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, false,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				ValidateAnswer: DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*7200.*"},
					FailIfNotMatchesRegexp: []string{".*7200.*"},
				},
			}, false,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				ValidateAuthority: DNSRRValidator{
					FailIfNotMatchesRegexp: []string{"ns.*.isp.net"},
				},
			}, true,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				ValidateAdditional: DNSRRValidator{
					FailIfNotMatchesRegexp: []string{"^ns.*.isp"},
				},
			}, true,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				ValidateAdditional: DNSRRValidator{
					FailIfMatchesRegexp: []string{"^ns.*.isp"},
				},
			}, false,
		},
	}
	expectedOutput := []string{
		"probe_dns_answer_rrs 1\n",
		"probe_dns_authority_rrs 2\n",
		"probe_dns_additional_rrs 3\n",
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, authoritativeDNSHandler)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.Protocol = protocol
			recorder := httptest.NewRecorder()
			result, _ := probeDNS(addr.String(), recorder, Module{Timeout: time.Second, DNS: test.Probe})
			if result != test.ShouldSucceed {
				t.Fatalf("Test %d had unexpected result: %v", i, result)
			}
			body := recorder.Body.String()
			for _, line := range expectedOutput {
				if !strings.Contains(body, line) {
					t.Fatalf("Did not find expected output in test %d: %q", i, line)
				}
			}
		}
	}
}

func TestServfailDNSResponse(t *testing.T) {
	tests := []struct {
		Probe         DNSProbe
		ShouldSucceed bool
	}{
		{
			DNSProbe{
				QueryName: "example.com",
			}, false,
		},
		{
			DNSProbe{
				QueryName:   "example.com",
				ValidRcodes: []string{"SERVFAIL", "NXDOMAIN"},
			}, true,
		},
		{
			DNSProbe{
				QueryName: "example.com",
				QueryType: "NOT_A_VALID_QUERY_TYPE",
			}, false,
		},
		{
			DNSProbe{
				QueryName:   "example.com",
				ValidRcodes: []string{"NOT_A_VALID_RCODE"},
			}, false,
		},
	}
	expectedOutput := []string{
		"probe_dns_answer_rrs 0\n",
		"probe_dns_authority_rrs 0\n",
		"probe_dns_additional_rrs 0\n",
	}

	for _, protocol := range PROTOCOLS {
		// dns.HandleFailed returns SERVFAIL on everything
		server, addr := startDNSServer(protocol, dns.HandleFailed)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.Protocol = protocol
			recorder := httptest.NewRecorder()
			result, _ := probeDNS(addr.String(), recorder, Module{Timeout: time.Second, DNS: test.Probe})
			if result != test.ShouldSucceed {
				t.Fatalf("Test %d had unexpected result: %v", i, result)
			}
			body := recorder.Body.String()
			for _, line := range expectedOutput {
				if !strings.Contains(body, line) {
					t.Fatalf("Did not find expected output in test %d: %q", i, line)
				}
			}
		}
	}
}

func TestDNSProtocol(t *testing.T) {
	// This test assumes that listening "tcp" listens both IPv6 and IPv4 traffic and
	// localhost resolves to both 127.0.0.1 and ::1. we must skip the test if either
	// of these isn't true. This should be true for modern Linux systems.
	if runtime.GOOS == "dragonfly" || runtime.GOOS == "openbsd" {
		t.Skip("IPv6 socket isn't able to accept IPv4 traffic in the system.")
	}
	_, err := net.ResolveIPAddr("ip6", "localhost")
	if err != nil {
		t.Skip("\"localhost\" doesn't resolve to ::1.")
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, recursiveDNSHandler)
		defer server.Shutdown()

		_, port, _ := net.SplitHostPort(addr.String())

		// Force IPv4
		module := Module{
			Timeout: time.Second,
			DNS: DNSProbe{
				QueryName: "example.com",
				Protocol:  protocol + "4",
			},
		}
		recorder := httptest.NewRecorder()
		result, _ := probeDNS(net.JoinHostPort("localhost", port), recorder, module)
		body := recorder.Body.String()
		if !result {
			t.Fatalf("DNS protocol: \"%v4\" connection test failed, expected success.", protocol)
		}
		if !strings.Contains(body, "probe_ip_protocol 4\n") {
			t.Fatalf("Expected IPv4, got %s", body)
		}

		// Force IPv6
		module = Module{
			Timeout: time.Second,
			DNS: DNSProbe{
				QueryName: "example.com",
				Protocol:  protocol + "6",
			},
		}
		recorder = httptest.NewRecorder()
		result, _ = probeDNS(net.JoinHostPort("localhost", port), recorder, module)
		body = recorder.Body.String()
		if !result {
			t.Fatalf("DNS protocol: \"%v6\" connection test failed, expected success.", protocol)
		}
		if !strings.Contains(body, "probe_ip_protocol 6\n") {
			t.Fatalf("Expected IPv6, got %s", body)
		}

		// Prefer IPv6
		module = Module{
			Timeout: time.Second,
			DNS: DNSProbe{
				QueryName:           "example.com",
				Protocol:            protocol,
				PreferredIPProtocol: "ip6",
			},
		}
		recorder = httptest.NewRecorder()
		result, _ = probeDNS(net.JoinHostPort("localhost", port), recorder, module)
		body = recorder.Body.String()
		if !result {
			t.Fatalf("DNS protocol: \"%v\", preferred \"ip6\" connection test failed, expected success.", protocol)
		}
		if !strings.Contains(body, "probe_ip_protocol 6\n") {
			t.Fatalf("Expected IPv6, got %s", body)
		}

		// Prefer IPv4
		module = Module{
			Timeout: time.Second,
			DNS: DNSProbe{
				QueryName:           "example.com",
				Protocol:            protocol,
				PreferredIPProtocol: "ip4",
			},
		}
		recorder = httptest.NewRecorder()
		result, _ = probeDNS(net.JoinHostPort("localhost", port), recorder, module)
		body = recorder.Body.String()
		if !result {
			t.Fatalf("DNS protocol: \"%v\", preferred \"ip4\" connection test failed, expected success.", protocol)
		}
		if !strings.Contains(body, "probe_ip_protocol 4\n") {
			t.Fatalf("Expected IPv4, got %s", body)
		}

		// Prefer none
		module = Module{
			Timeout: time.Second,
			DNS: DNSProbe{
				QueryName: "example.com",
				Protocol:  protocol,
			},
		}
		recorder = httptest.NewRecorder()
		result, _ = probeDNS(net.JoinHostPort("localhost", port), recorder, module)
		body = recorder.Body.String()
		if !result {
			t.Fatalf("DNS protocol: \"%v\" connection test failed, expected success.", protocol)
		}
		if !strings.Contains(body, "probe_ip_protocol 6\n") {
			t.Fatalf("Expected IPv6, got %s", body)
		}

		// No protocol
		module = Module{
			Timeout: time.Second,
			DNS: DNSProbe{
				QueryName: "example.com",
			},
		}
		recorder = httptest.NewRecorder()
		result, _ = probeDNS(net.JoinHostPort("localhost", port), recorder, module)
		body = recorder.Body.String()
		if protocol == "udp" {
			if !result {
				t.Fatalf("DNS test connection with protocol %s failed, expected success.", protocol)
			}
		} else {
			if result {
				t.Fatalf("DNS test connection with protocol %s succeeded, expected failure.", protocol)
			}
		}
		if !strings.Contains(body, "probe_ip_protocol 6\n") {
			t.Fatalf("Expected IPv6, got %s", body)
		}
	}
}
