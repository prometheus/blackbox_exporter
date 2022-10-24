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

package config

import (
	"errors"
	"gopkg.in/yaml.v3"
	"net"
	"strings"
	"testing"
)

var anyIP = []string{
	"127.0.0.1",
	"10.1.2.3",
	"192.0.2.1",
	"2002::1",
	"::1",
}

func TestIPFilter(t *testing.T) {
	for title, tc := range map[string]struct {
		input    string
		err      error
		defAllow bool
		accepts  []string
		rejects  []string
	}{
		"empty": {
			input:    `{}`,
			defAllow: true,
			accepts:  anyIP,
		},
		"allow all": {
			input:    `default: allow`,
			defAllow: true,
			accepts:  anyIP,
		},
		"deny all": {
			input:    `default: deny`,
			defAllow: false,
			rejects:  anyIP,
		},
		"implicit allow": {
			input:    `denied: [ "127.0.0.0/8" ]`,
			defAllow: true,
			accepts: []string{
				"10.1.2.3",
				"192.168.123.10",
				"198.51.100.250",
			},
			rejects: []string{
				"127.0.0.1",
				"127.255.255.255",
			},
		},
		"implicit deny": {
			input:    `allowed: [ "127.0.0.0/8" ]`,
			defAllow: false,
			rejects: []string{
				"10.1.2.3",
				"192.168.123.10",
				"198.51.100.250",
			},
			accepts: []string{
				"127.0.0.1",
				"127.255.255.255",
			},
		},
		"required default": {
			input: `
allowed: [ "127.0.0.1/32" ]
denied: [ "127.0.0.2/32" ]`,
			err: errors.New("missing field ip_filter.default"),
		},
		"invalid default": {
			input: `default: drop`,
			err:   errors.New("unsupported value for ip_filter.default, use `allowed` or `denied`"),
		},
		"invalid allowed network": {
			input: `allowed: [ "10.20.30.40" ]`,
			err:   errors.New("invalid CIDR address: 10.20.30.40"),
		},
		"invalid denied network": {
			input: `denied: [ "10.20.30.40" ]`,
			err:   errors.New("invalid CIDR address: 10.20.30.40"),
		},
		"invalid type": {
			input: `allowed: "10.0.0.0/8"`,
			err:   errors.New("yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `10.0.0.0/8` into []string"),
		},
		"longest prefix match": {
			input: `
default: deny
allowed: [ "10.0.0.0/8", "192.168.0.0/16" ]
denied: [ "10.0.1.1/32", "192.168.255.0/24" ]
`,
			accepts: []string{
				"10.1.2.3",
				"10.0.1.2",
				"192.168.1.2",
			},
			rejects: []string{
				"10.0.1.1",
				"192.168.255.30",
				"203.0.113.2",
			},
		},
	} {
		t.Run(title, func(t *testing.T) {
			var ipf IPFilter
			decoder := yaml.NewDecoder(strings.NewReader(tc.input))
			decoder.KnownFields(true)
			err := decoder.Decode(&ipf)
			if (err != nil) != (tc.err != nil) || err != nil && err.Error() != tc.err.Error() {
				t.Fatalf("expected error `%v` but got `%v`", tc.err, err)
			}
			if ipf.defaultAllow != tc.defAllow {
				t.Fatal("invalid default. expected:", tc.defAllow, "actual:", ipf.defaultAllow)
			}
			checkList(t, &ipf, tc.accepts, true)
			checkList(t, &ipf, tc.rejects, false)
		})
	}
}

func TestIPFilterNilOrZero(t *testing.T) {
	mod := Module{}
	checkList(t, mod.IPFilter, anyIP, true)
	checkList(t, &IPFilter{}, anyIP, true)
}

func newIPFilter(t *testing.T, allowed []string, denied []string, def bool) *IPFilter {
	a, err := parseCIDRNets(allowed)
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseCIDRNets(denied)
	if err != nil {
		t.Fatal(err)
	}
	ipf, err := NewIPFilter(a, d, def)
	if err != nil {
		t.Fatal(err)
	}
	return ipf
}

func TestNewIPFilterToYAML(t *testing.T) {
	for title, tc := range map[string]struct {
		ipf      *IPFilter
		expected string
	}{
		"implicit deny": {
			ipf: newIPFilter(t, []string{"10.0.0.0/8"}, nil, false),
			expected: `ip_filter:
	allowed:
		- 10.0.0.0/8
`,
		},
		"implicit allow": {
			ipf: newIPFilter(t, nil, []string{"10.0.0.0/8"}, true),
			expected: `ip_filter:
	denied:
		- 10.0.0.0/8
`,
		},
		"explicit deny": {
			ipf: newIPFilter(t, nil, []string{"10.0.0.0/8"}, false),
			expected: `ip_filter:
	default: deny
	denied:
		- 10.0.0.0/8
`,
		},
		"explicit allow": {
			ipf: newIPFilter(t, []string{"10.0.0.0/8"}, nil, true),
			expected: `ip_filter:
	allowed:
		- 10.0.0.0/8
	default: allow
`,
		},
		"complex allow": {
			ipf: newIPFilter(t, []string{"10.0.0.0/8"}, []string{"2002::1/64"}, true),
			expected: `ip_filter:
	allowed:
		- 10.0.0.0/8
	default: allow
	denied:
		- 2002::/64
`,
		},
		"complex deny": {
			ipf: newIPFilter(t, []string{"10.0.0.0/8"}, []string{"2002::1/64"}, false),
			expected: `ip_filter:
	allowed:
		- 10.0.0.0/8
	default: deny
	denied:
		- 2002::/64
`,
		},
		"nil": {
			expected: "{}\n",
		},
	} {
		t.Run(title, func(t *testing.T) {
			body := struct {
				IPFilter *IPFilter `yaml:"ip_filter,omitempty"`
			}{
				IPFilter: tc.ipf,
			}
			b, err := yaml.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			exp := strings.ReplaceAll(tc.expected, "\t", "    ")
			if string(b) != exp {
				t.Fatalf("yaml doesn't match. Expected: `%s` actual: `%s`",
					exp, string(b))
			}
		})
	}
}

func checkList(t *testing.T, ipf *IPFilter, lst []string, expected bool) {
	t.Helper()
	for _, addr := range lst {
		if ipf.IsAllowed(net.ParseIP(addr)) != expected {
			t.Fatal("allow test failed for", addr, "expected:", expected, "actual:", !expected)
		}
	}
}
