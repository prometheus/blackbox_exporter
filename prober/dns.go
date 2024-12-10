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
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

// validRRs checks a slice of RRs received from the server against a DNSRRValidator.
func validRRs(rrType string, rrs *[]dns.RR, v *config.DNSRRValidator, logger *slog.Logger) ProbeResult {
	logger.Info("Validating " + rrType)
	failure_reason := rrType + " validation Failed"
	var anyMatch = false
	var allMatch = true
	// Fail the probe if there are no RRs of a given type, but a regexp match is required
	// (i.e. FailIfNotMatchesRegexp or FailIfNoneMatchesRegexp is set).
	if len(*rrs) == 0 && len(v.FailIfNotMatchesRegexp) > 0 {
		return ProbeFailure(failure_reason, "problem", "fail_if_not_matches_regexp specified but no RRs returned")
	}
	if len(*rrs) == 0 && len(v.FailIfNoneMatchesRegexp) > 0 {
		return ProbeFailure(failure_reason, "problem", "fail_if_none_matches_regexp specified but no RRs returned")
	}
	for _, rr := range *rrs {
		logger.Info("Validating RR", "rr", rr)
		for _, re := range v.FailIfMatchesRegexp {
			match, err := regexp.MatchString(re, rr.String())
			if err != nil {
				return ProbeFailure(failure_reason, "problem", "Error matching regexp", "regexp", re, "err", err.Error())
			}
			if match {
				return ProbeFailure(failure_reason, "problem", "At least one RR matched regexp", "regexp", re, "rr", rr.String())
			}
		}
		for _, re := range v.FailIfAllMatchRegexp {
			match, err := regexp.MatchString(re, rr.String())
			if err != nil {
				return ProbeFailure(failure_reason, "problem", "Error matching regexp", "regexp", re, "err", err.Error())
			}
			if !match {
				allMatch = false
			}
		}
		for _, re := range v.FailIfNotMatchesRegexp {
			match, err := regexp.MatchString(re, rr.String())
			if err != nil {
				return ProbeFailure(failure_reason, "problem", "Error matching regexp", "regexp", re, "err", err.Error())
			}
			if !match {
				return ProbeFailure(failure_reason, "problem", "At least one RR did not match regexp", "regexp", re, "rr", rr.String())
			}
		}
		for _, re := range v.FailIfNoneMatchesRegexp {
			match, err := regexp.MatchString(re, rr.String())
			if err != nil {
				return ProbeFailure(failure_reason, "problem", "Error matching regexp", "regexp", re, "err", err.Error())
			}
			if match {
				anyMatch = true
			}
		}
	}
	if len(v.FailIfAllMatchRegexp) > 0 && !allMatch {
		return ProbeFailure(failure_reason, "problem", "Not all RRs matched regexp")
	}
	if len(v.FailIfNoneMatchesRegexp) > 0 && !anyMatch {
		return ProbeFailure(failure_reason, "problem", "None of the RRs did matched any regexp")
	}
	return ProbeSuccess()
}

// validRcode checks rcode in the response against a list of valid rcodes.
func validRcode(rcode int, valid []string, logger *slog.Logger) ProbeResult {
	var validRcodes []int
	// If no list of valid rcodes is specified, only NOERROR is considered valid.
	if valid == nil {
		validRcodes = append(validRcodes, dns.StringToRcode["NOERROR"])
	} else {
		for _, rcode := range valid {
			rc, ok := dns.StringToRcode[rcode]
			if !ok {
				logger.Info("Known rcodes", "known_rcode", dns.RcodeToString)
				return ProbeFailure("Invalid rcode", "rcode", rcode)
			}
			validRcodes = append(validRcodes, rc)
		}
	}
	for _, rc := range validRcodes {
		if rcode == rc {
			logger.Info("Rcode is valid", "rcode", rcode, "string_rcode", dns.RcodeToString[rcode])
			return ProbeSuccess()
		}
	}
	logger.Info("Valid Rrcodes", "valid_rcodes", validRcodes)
	return ProbeFailure("Rcode is not one of the valid rcodes", "rcode", strconv.Itoa(rcode), "string_rcode", dns.RcodeToString[rcode])
}

func ProbeDNS(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) ProbeResult {
	var dialProtocol string
	probeDNSDurationGaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_dns_duration_seconds",
		Help: "Duration of DNS request by phase",
	}, []string{"phase"})
	probeDNSAnswerRRSGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_answer_rrs",
		Help: "Returns number of entries in the answer resource record list",
	})
	probeDNSAuthorityRRSGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_authority_rrs",
		Help: "Returns number of entries in the authority resource record list",
	})
	probeDNSAdditionalRRSGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_additional_rrs",
		Help: "Returns number of entries in the additional resource record list",
	})
	probeDNSQuerySucceeded := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_query_succeeded",
		Help: "Displays whether or not the query was executed successfully",
	})

	for _, lv := range []string{"resolve", "connect", "request"} {
		probeDNSDurationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(probeDNSDurationGaugeVec)
	registry.MustRegister(probeDNSAnswerRRSGauge)
	registry.MustRegister(probeDNSAuthorityRRSGauge)
	registry.MustRegister(probeDNSAdditionalRRSGauge)
	registry.MustRegister(probeDNSQuerySucceeded)

	qc := uint16(dns.ClassINET)
	if module.DNS.QueryClass != "" {
		var ok bool
		qc, ok = dns.StringToClass[module.DNS.QueryClass]
		if !ok {
			logger.Info("Existing query classes", "existing_classes", dns.ClassToString)
			return ProbeFailure("Invalid query class", "Class seen", module.DNS.QueryClass)
		}
	}

	qt := dns.TypeANY
	if module.DNS.QueryType != "" {
		var ok bool
		qt, ok = dns.StringToType[module.DNS.QueryType]
		if !ok {
			logger.Info("Existing query types", "existing_types", dns.TypeToString)
			return ProbeFailure("Invalid query type", "Type seen", module.DNS.QueryType)
		}
	}
	var probeDNSSOAGauge prometheus.Gauge

	var ip *net.IPAddr
	if module.DNS.TransportProtocol == "" {
		module.DNS.TransportProtocol = "udp"
	}
	if module.DNS.TransportProtocol != "udp" && module.DNS.TransportProtocol != "tcp" {
		return ProbeFailure("Configuration error: Expected transport protocol udp or tcp", "protocol", module.DNS.TransportProtocol)
	}

	targetAddr, port, err := net.SplitHostPort(target)
	if err != nil {
		// Target only contains host so fallback to default port and set targetAddr as target.
		if module.DNS.DNSOverTLS {
			port = "853"
		} else {
			port = "53"
		}
		targetAddr = target
	}
	ip, lookupTime, err := chooseProtocol(ctx, module.DNS.IPProtocol, module.DNS.IPProtocolFallback, targetAddr, registry, logger)
	if err != nil {
		return ProbeFailure("Error resolving address", "err", err.Error())
	}
	probeDNSDurationGaugeVec.WithLabelValues("resolve").Add(lookupTime)
	targetIP := net.JoinHostPort(ip.String(), port)

	if ip.IP.To4() == nil {
		dialProtocol = module.DNS.TransportProtocol + "6"
	} else {
		dialProtocol = module.DNS.TransportProtocol + "4"
	}

	if module.DNS.DNSOverTLS {
		if module.DNS.TransportProtocol == "tcp" {
			dialProtocol += "-tls"
		} else {
			return ProbeFailure("Configuration error: Expected transport protocol tcp for DoT", "protocol", module.DNS.TransportProtocol)
		}
	}

	client := new(dns.Client)
	client.Net = dialProtocol

	if module.DNS.DNSOverTLS {
		tlsConfig, err := pconfig.NewTLSConfig(&module.DNS.TLSConfig)
		if err != nil {
			return ProbeFailure("Failed to create TLS configuration", "err", err.Error())
		}
		if tlsConfig.ServerName == "" {
			// Use target-hostname as default for TLS-servername.
			tlsConfig.ServerName = targetAddr
		}

		client.TLSConfig = tlsConfig
	}

	// Use configured SourceIPAddress.
	if len(module.DNS.SourceIPAddress) > 0 {
		srcIP := net.ParseIP(module.DNS.SourceIPAddress)
		if srcIP == nil {
			return ProbeFailure("Error parsing source ip address", "srcIP", module.DNS.SourceIPAddress)
		}
		logger.Info("Using local address", "srcIP", srcIP)
		client.Dialer = &net.Dialer{}
		if module.DNS.TransportProtocol == "tcp" {
			client.Dialer.LocalAddr = &net.TCPAddr{IP: srcIP}
		} else {
			client.Dialer.LocalAddr = &net.UDPAddr{IP: srcIP}
		}
	}

	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = module.DNS.Recursion
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{dns.Fqdn(module.DNS.QueryName), qt, qc}

	logger.Info("Making DNS query", "target", targetIP, "dial_protocol", dialProtocol, "query", module.DNS.QueryName, "type", qt, "class", qc)
	timeoutDeadline, _ := ctx.Deadline()
	client.Timeout = time.Until(timeoutDeadline)
	requestStart := time.Now()
	response, rtt, err := client.Exchange(msg, targetIP)
	// The rtt value returned from client.Exchange includes only the time to
	// exchange messages with the server _after_ the connection is created.
	// We compute the connection time as the total time for the operation
	// minus the time for the actual request rtt.
	probeDNSDurationGaugeVec.WithLabelValues("connect").Set((time.Since(requestStart) - rtt).Seconds())
	probeDNSDurationGaugeVec.WithLabelValues("request").Set(rtt.Seconds())
	if err != nil {
		return ProbeFailure("Error while sending a DNS query", "err", err.Error())
	}
	logger.Info("Got response", "response", response)

	probeDNSAnswerRRSGauge.Set(float64(len(response.Answer)))
	probeDNSAuthorityRRSGauge.Set(float64(len(response.Ns)))
	probeDNSAdditionalRRSGauge.Set(float64(len(response.Extra)))
	probeDNSQuerySucceeded.Set(1)

	if qt == dns.TypeSOA {
		probeDNSSOAGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_dns_serial",
			Help: "Returns the serial number of the zone",
		})
		registry.MustRegister(probeDNSSOAGauge)

		for _, a := range response.Answer {
			if soa, ok := a.(*dns.SOA); ok {
				probeDNSSOAGauge.Set(float64(soa.Serial))
			}
		}
	}

	result := validRcode(response.Rcode, module.DNS.ValidRcodes, logger)
	if result.success {
		result = validRRs("Answer RRs", &response.Answer, &module.DNS.ValidateAnswer, logger)
	}
	if result.success {
		result = validRRs("Authority RRs", &response.Ns, &module.DNS.ValidateAuthority, logger)
	}
	if result.success {
		result = validRRs("Additional RRs", &response.Extra, &module.DNS.ValidateAdditional, logger)
	}
	return result
}
