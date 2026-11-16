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

package main

import (
	"net"

	"github.com/miekg/dns"
)

func serveDNS(pc net.PacketConn) {
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(handleDNS)}
	fatal(srv.ActivateAndServe())
}

// answers are the only records badserver serves. Any other query gets NXDOMAIN.
var answers = map[dns.Question]string{
	{Name: "www.e2e.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}: "www.e2e.test. 300 IN A 192.0.2.10",
}

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = dns.RcodeNameError
	if len(req.Question) == 1 {
		if s, ok := answers[req.Question[0]]; ok {
			rr, err := dns.NewRR(s)
			fatal(err)
			m.Answer, m.Rcode = []dns.RR{rr}, dns.RcodeSuccess
		}
	}
	w.WriteMsg(m)
}
