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
	"fmt"
	"net/http"
	"regexp"

	"github.com/miekg/dns"
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

func probeDNS(target string, w http.ResponseWriter, module Module) bool {
	var numAnswer, numAuthority, numAdditional int
	defer func() {
		// These metrics can be used to build additional alerting based on the number of replies.
		// They should be returned even in case of errors.
		fmt.Fprintf(w, "probe_dns_answer_rrs %d\n", numAnswer)
		fmt.Fprintf(w, "probe_dns_authority_rrs %d\n", numAuthority)
		fmt.Fprintf(w, "probe_dns_additional_rrs %d\n", numAdditional)
	}()

	client := new(dns.Client)
	client.Net = module.DNS.Protocol
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
