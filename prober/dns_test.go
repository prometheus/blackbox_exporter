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
	"context"
	"net"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

var PROTOCOLS = [...]string{"udp", "tcp"}

// startDNSServer starts a DNS server with a given handler function on a random port.
// Returns the Server object itself as well as the net.Addr corresponding to the server port.
func startDNSServer(protocol string, handler func(dns.ResponseWriter, *dns.Msg)) (*dns.Server, net.Addr) {
	h := dns.NewServeMux()
	h.HandleFunc(".", handler)

	server := &dns.Server{Addr: ":0", Net: protocol, Handler: h}
	if protocol == "udp" {
		a, err := net.ResolveUDPAddr(server.Net, server.Addr)
		if err != nil {
			panic(err)
		}
		l, err := net.ListenUDP(server.Net, a)
		if err != nil {
			panic(err)
		}
		server.PacketConn = l
	} else {
		a, err := net.ResolveTCPAddr(server.Net, server.Addr)
		if err != nil {
			panic(err)
		}
		l, err := net.ListenTCP(server.Net, a)
		if err != nil {
			panic(err)
		}
		server.Listener = l
	}
	go server.ActivateAndServe()

	if protocol == "tcp" {
		return server, server.Listener.Addr()
	}
	return server, server.PacketConn.LocalAddr()
}

func recursiveDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if !r.RecursionDesired {
		m.Rcode = dns.RcodeRefused
	} else {
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
	}
	if err := w.WriteMsg(m); err != nil {
		panic(err)
	}
}

func TestRecursiveDNSResponse(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	tests := []struct {
		Probe          config.DNSProbe
		expectedResult ProbeResult
	}{
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
				ValidRcodes:        []string{"SERVFAIL", "NXDOMAIN"},
			}, ProbeFailure("Rcode is not one of the valid rcodes", "rcode", "0", "string_rcode",
				"NOERROR"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
				ValidateAnswer: config.DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*7200.*"},
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
				ValidateAuthority: config.DNSRRValidator{
					FailIfMatchesRegexp: []string{".*7200.*"},
				},
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
				ValidateAdditional: config.DNSRRValidator{
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, ProbeFailure("Additional RRs validation Failed", "problem", "fail_if_not_matches_regexp specified but no RRs returned"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          false,
			}, ProbeFailure("Rcode is not one of the valid rcodes", "rcode", "5", "string_rcode", "REFUSED"),
		},
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, recursiveDNSHandler)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.TransportProtocol = protocol
			registry := prometheus.NewPedanticRegistry()
			registry.Gather()

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeDNS(testCTX, addr.String(), config.Module{Timeout: time.Second, DNS: test.Probe}, registry, promslog.NewNopLogger())
			if !reflect.DeepEqual(result, test.expectedResult) {
				t.Fatalf("Test %d had unexpected result: expected %v, got %v", i, test.expectedResult, result)
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_dns_answer_rrs":      2,
				"probe_dns_authority_rrs":   0,
				"probe_dns_additional_rrs":  0,
				"probe_dns_query_succeeded": 1,
			}
			if !test.Probe.Recursion {
				expectedResults["probe_dns_answer_rrs"] = 0
			}
			checkRegistryResults(expectedResults, mfs, t)
		}
	}
}

func authoritativeDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if r.Question[0].Qtype == dns.TypeSOA {
		a, err := dns.NewRR("example.com. 3600 IN SOA ns.example.com. noc.example.com. 1000 7200 3600 1209600 3600")
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, a)
	} else if r.Question[0].Qclass == dns.ClassCHAOS && r.Question[0].Qtype == dns.TypeTXT {
		txt, err := dns.NewRR("example.com. 3600 CH TXT \"goCHAOS\"")
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, txt)
	} else {
		a, err := dns.NewRR("example.com. 3600 IN A 127.0.0.1")
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, a)
	}

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
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	tests := []struct {
		Probe          config.DNSProbe
		expectedResult ProbeResult
	}{
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				QueryType:          "SOA",
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryClass:         "CH",
				QueryName:          "example.com",
				QueryType:          "TXT",
				ValidateAnswer: config.DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*IN.*"},
					FailIfNotMatchesRegexp: []string{".*CH.*"},
				},
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidRcodes:        []string{"SERVFAIL", "NXDOMAIN"},
			}, ProbeFailure("Rcode is not one of the valid rcodes", "rcode", "0", "string_rcode", "NOERROR"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAnswer: config.DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*3600.*"},
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, ProbeFailure("Answer RRs validation Failed", "problem", "At least one RR matched regexp", "regexp", ".*3600.*"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAnswer: config.DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*7200.*"},
					FailIfNotMatchesRegexp: []string{".*7200.*"},
				},
			}, ProbeFailure("Answer RRs validation Failed", "problem", "At least one RR did not match regexp", "regexp", ".*7200.*"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAuthority: config.DNSRRValidator{
					FailIfNotMatchesRegexp: []string{"ns.*.isp.net"},
				},
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAdditional: config.DNSRRValidator{
					FailIfNotMatchesRegexp: []string{"^ns.*.isp"},
				},
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAdditional: config.DNSRRValidator{
					FailIfMatchesRegexp: []string{"^ns.*.isp"},
				},
			}, ProbeFailure("Additional RRs validation Failed", "problem", "At least one RR matched regexp", "regexp", "^ns.*.isp"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAdditional: config.DNSRRValidator{
					FailIfAllMatchRegexp: []string{".*127.0.0.*"},
				},
			}, ProbeFailure("Additional RRs validation Failed", "problem", "Not all RRs matched regexp"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAdditional: config.DNSRRValidator{
					FailIfNoneMatchesRegexp: []string{".*127.0.0.3.*"},
				},
			}, ProbeFailure("Additional RRs validation Failed", "problem", "None of the RRs did matched any regexp"),
		},
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, authoritativeDNSHandler)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.TransportProtocol = protocol
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeDNS(testCTX, addr.String(), config.Module{Timeout: time.Second, DNS: test.Probe}, registry, promslog.NewNopLogger())
			if !reflect.DeepEqual(result, test.expectedResult) {
				t.Fatalf("Test %d had unexpected result: expected %v, got %v", i, test.expectedResult, result)
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_dns_answer_rrs":      1,
				"probe_dns_authority_rrs":   2,
				"probe_dns_additional_rrs":  3,
				"probe_dns_query_succeeded": 1,
			}
			if test.Probe.QueryType == "SOA" {
				expectedResults["probe_dns_serial"] = 1000
			}

			checkRegistryResults(expectedResults, mfs, t)
		}
	}
}

func TestServfailDNSResponse(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	tests := []struct {
		Probe          config.DNSProbe
		expectedResult ProbeResult
	}{
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
			}, ProbeFailure("Rcode is not one of the valid rcodes", "rcode", "2", "string_rcode", "SERVFAIL"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidRcodes:        []string{"SERVFAIL", "NXDOMAIN"},
			}, ProbeSuccess(),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				QueryType:          "NOT_A_VALID_QUERY_TYPE",
			}, ProbeFailure("Invalid query type", "Type seen", "NOT_A_VALID_QUERY_TYPE"),
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidRcodes:        []string{"NOT_A_VALID_RCODE"},
			}, ProbeFailure("Invalid rcode", "rcode", "NOT_A_VALID_RCODE"),
		},
	}

	for _, protocol := range PROTOCOLS {
		// dns.HandleFailed returns SERVFAIL on everything
		server, addr := startDNSServer(protocol, dns.HandleFailed)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.TransportProtocol = protocol
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeDNS(testCTX, addr.String(), config.Module{Timeout: time.Second, DNS: test.Probe}, registry, promslog.NewNopLogger())
			if !reflect.DeepEqual(result, test.expectedResult) {
				t.Fatalf("Test %d had unexpected result: expected %v, got %v", i, test.expectedResult, result)
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_dns_answer_rrs":      0,
				"probe_dns_authority_rrs":   0,
				"probe_dns_additional_rrs":  0,
				"probe_dns_query_succeeded": 1,
			}

			// Handle case where ProbeDNS fails before executing the query because of an invalid query type
			if test.Probe.QueryType == "NOT_A_VALID_QUERY_TYPE" {
				expectedResults["probe_dns_query_succeeded"] = 0
			}

			checkRegistryResults(expectedResults, mfs, t)
		}
	}
}

func TestDNSProtocol(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	// This test assumes that listening TCP listens both IPv6 and IPv4 traffic and
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

		// Prefer IPv6
		module := config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				QueryName:         "example.com",
				TransportProtocol: protocol,
				IPProtocol:        "ip6",
				Recursion:         true,
			},
		}
		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result := ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
		if !result.success {
			t.Fatalf("DNS protocol: \"%v\", preferred \"ip6\" connection test failed, expected success.", protocol)
			t.Fatalf("Failure reason: %v", result)
		}
		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedResults := map[string]float64{
			"probe_ip_protocol": 6,
		}
		checkRegistryResults(expectedResults, mfs, t)

		// Prefer IPv4
		module = config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				QueryName:         "example.com",
				Recursion:         true,
				TransportProtocol: protocol,
				IPProtocol:        "ip4",
			},
		}
		registry = prometheus.NewRegistry()
		testCTX, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
		if !result.success {
			t.Fatalf("DNS protocol: \"%v\", preferred \"ip4\" connection test failed, expected success.", protocol)
			t.Fatalf("Failure reason: %v", result)
		}
		mfs, err = registry.Gather()
		if err != nil {
			t.Fatal(err)
		}

		expectedResults = map[string]float64{
			"probe_ip_protocol": 4,
		}
		checkRegistryResults(expectedResults, mfs, t)

		// Prefer none
		module = config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				QueryName:         "example.com",
				Recursion:         true,
				TransportProtocol: protocol,
			},
		}
		registry = prometheus.NewRegistry()
		testCTX, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
		if !result.success {
			t.Fatalf("DNS protocol: \"%v\" connection test failed, expected success.", protocol)
			t.Fatalf("Failure reason: %v", result)
		}
		mfs, err = registry.Gather()
		if err != nil {
			t.Fatal(err)
		}

		expectedResults = map[string]float64{
			"probe_ip_protocol": 6,
		}
		checkRegistryResults(expectedResults, mfs, t)

		// No protocol
		module = config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				QueryName: "example.com",
				Recursion: true,
			},
		}
		registry = prometheus.NewRegistry()
		testCTX, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
		if protocol == "udp" {
			if !result.success {
				t.Fatalf("DNS test connection with protocol %s failed, expected success.", protocol)
				t.Fatalf("Failure reason: %v", result)
			}
		} else {
			if result.success {
				t.Fatalf("DNS test connection with protocol %s succeeded, expected failure.", protocol)
				expectedReason := ProbeFailure("todo")
				if !reflect.DeepEqual(result, expectedReason) {
					t.Fatalf("Test unexpected result: expected %v, got %v", expectedReason, result)
				}
			}
		}
		mfs, err = registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedResults = map[string]float64{
			"probe_ip_protocol": 6,
		}
		checkRegistryResults(expectedResults, mfs, t)

	}
}

// TestDNSMetrics checks that calling ProbeDNS populates the expected
// set of metrics for a DNS probe, but it does not test that those
// metrics contain specific values.
func TestDNSMetrics(t *testing.T) {
	server, addr := startDNSServer("udp", recursiveDNSHandler)
	defer server.Shutdown()

	_, port, _ := net.SplitHostPort(addr.String())

	module := config.Module{
		Timeout: time.Second,
		DNS: config.DNSProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			QueryName:          "example.com",
			Recursion:          true,
		},
	}
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
	if !result.success {
		t.Fatalf("DNS test connection failed, expected success.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedMetrics := map[string]map[string]map[string]struct{}{
		"probe_dns_lookup_time_seconds": nil,
		"probe_dns_duration_seconds": {
			"phase": {
				"resolve": {},
				"connect": {},
				"request": {},
			},
		},
		"probe_dns_answer_rrs":      nil,
		"probe_dns_authority_rrs":   nil,
		"probe_dns_additional_rrs":  nil,
		"probe_dns_query_succeeded": nil,
	}

	checkMetrics(expectedMetrics, mfs, t)
}
