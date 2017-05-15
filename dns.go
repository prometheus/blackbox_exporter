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
	"net/http"
	"regexp"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

// validRRs checks a slice of RRs received from the server against a DNSRRValidator.
func validRRs(rrs *[]dns.RR, v *DNSRRValidator) bool {
	// Fail the probe if there are no RRs of a given type, but a regexp match is required
	// (i.e. FailIfNotMatchesRegexp is set).
	if len(*rrs) == 0 && len(v.FailIfNotMatchesRegexp) > 0 {
		return false
	}
	for _, rr := range *rrs {
		log.Debugf("Validating RR: %q", rr)
		for _, re := range v.FailIfMatchesRegexp {
			match, err := regexp.MatchString(re, rr.String())
			if err != nil {
				log.Errorf("Error matching regexp %q: %s", re, err)
				return false
			}
			if match {
				return false
			}
		}
		for _, re := range v.FailIfNotMatchesRegexp {
			match, err := regexp.MatchString(re, rr.String())
			if err != nil {
				log.Errorf("Error matching regexp %q: %s", re, err)
				return false
			}
			if !match {
				return false
			}
		}
	}
	return true
}

// validRcode checks rcode in the response against a list of valid rcodes.
func validRcode(rcode int, valid []string) bool {
	var validRcodes []int
	// If no list of valid rcodes is specified, only NOERROR is considered valid.
	if valid == nil {
		validRcodes = append(validRcodes, dns.StringToRcode["NOERROR"])
	} else {
		for _, rcode := range valid {
			rc, ok := dns.StringToRcode[rcode]
			if !ok {
				log.Errorf("Invalid rcode %v. Existing rcodes: %v", rcode, dns.RcodeToString)
				return false
			}
			validRcodes = append(validRcodes, rc)
		}
	}
	for _, rc := range validRcodes {
		if rcode == rc {
			return true
		}
	}
	log.Debugf("%s (%d) is not one of the valid rcodes (%v)", dns.RcodeToString[rcode], rcode, validRcodes)
	return false
}

func probeDNS(target string, w http.ResponseWriter, module Module, registry *prometheus.Registry) bool {
	var numAnswer, numAuthority, numAdditional int
	var dialProtocol, fallbackProtocol string
	probeIPProtocolGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_protocol",
		Help: "Specifies whether probe ip protocl is IP4 or IP6",
	})
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
	registry.MustRegister(probeIPProtocolGauge)
	registry.MustRegister(probeDNSAnswerRRSGauge)
	registry.MustRegister(probeDNSAuthorityRRSGauge)
	registry.MustRegister(probeDNSAdditionalRRSGauge)

	defer func() {
		// These metrics can be used to build additional alerting based on the number of replies.
		// They should be returned even in case of errors.
		probeDNSAnswerRRSGauge.Set(float64(numAnswer))
		probeDNSAuthorityRRSGauge.Set(float64(numAuthority))
		probeDNSAdditionalRRSGauge.Set(float64(numAdditional))
	}()

	if module.DNS.Protocol == "" {
		module.DNS.Protocol = "udp"
	}

	if (module.DNS.Protocol == "tcp" || module.DNS.Protocol == "udp") && module.DNS.PreferredIPProtocol == "" {
		module.DNS.PreferredIPProtocol = "ip6"
	}
	if module.DNS.PreferredIPProtocol == "ip6" {
		fallbackProtocol = "ip4"
	} else {
		fallbackProtocol = "ip6"
	}

	dialProtocol = module.DNS.Protocol
	if module.DNS.Protocol == "udp" || module.DNS.Protocol == "tcp" {
		targetAddress, _, _ := net.SplitHostPort(target)
		ip, err := net.ResolveIPAddr(module.DNS.PreferredIPProtocol, targetAddress)
		if err != nil {
			ip, err = net.ResolveIPAddr(fallbackProtocol, targetAddress)
			if err != nil {
				return false
			}
		}

		if ip.IP.To4() == nil {
			dialProtocol = module.DNS.Protocol + "6"
		} else {
			dialProtocol = module.DNS.Protocol + "4"
		}
	}

	if dialProtocol[len(dialProtocol)-1] == '6' {
		probeIPProtocolGauge.Set(6)
	} else {
		probeIPProtocolGauge.Set(4)
	}

	client := new(dns.Client)
	client.Net = dialProtocol
	client.Timeout = module.Timeout

	qt := dns.TypeANY
	if module.DNS.QueryType != "" {
		var ok bool
		qt, ok = dns.StringToType[module.DNS.QueryType]
		if !ok {
			log.Errorf("Invalid type %v. Existing types: %v", module.DNS.QueryType, dns.TypeToString)
			return false
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(module.DNS.QueryName), qt)

	response, _, err := client.Exchange(msg, target)
	if err != nil {
		log.Warnf("Error while sending a DNS query: %s", err)
		return false
	}
	log.Debugf("Got response: %#v", response)

	numAnswer, numAuthority, numAdditional = len(response.Answer), len(response.Ns), len(response.Extra)

	if !validRcode(response.Rcode, module.DNS.ValidRcodes) {
		return false
	}
	if !validRRs(&response.Answer, &module.DNS.ValidateAnswer) {
		log.Debugf("Answer RRs validation failed")
		return false
	}
	if !validRRs(&response.Ns, &module.DNS.ValidateAuthority) {
		log.Debugf("Authority RRs validation failed")
		return false
	}
	if !validRRs(&response.Extra, &module.DNS.ValidateAdditional) {
		log.Debugf("Additional RRs validation failed")
		return false
	}
	return true
}
