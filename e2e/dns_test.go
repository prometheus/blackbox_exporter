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

const dnsServer = "badserver:30053"

var dnsCases = []probeCase{
	{
		prober: "dns", name: "ipv6", target: dnsServer, want: 1, metrics: usedIP(6),
		module: `{` + ip6Only + `, query_name: www.e2e.test, query_type: A, validate_answer_rrs: {fail_if_not_matches_regexp: ['192\.0\.2\.10']}}`,
	},
}

func TestDNS(t *testing.T) { runCases(t, dnsCases) }
