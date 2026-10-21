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

//go:build !windows

package config

import (
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestTOSUnmarshal is not built on windows, where the config loader rejects
// a non-zero "tos".
func TestTOSUnmarshal(t *testing.T) {
	configStr := `
modules:
  http_tos:
    prober: http
    http:
      tos: 0x28
  tcp_tos:
    prober: tcp
    tcp:
      tos: 184
  dns_tos:
    prober: dns
    dns:
      query_name: example.com
      tos: 0x20
  icmp_tos:
    prober: icmp
    icmp:
      tos: 255
  icmp_default:
    prober: icmp
`
	var c Config
	if err := yaml.Unmarshal([]byte(configStr), &c); err != nil {
		t.Fatalf("Error unmarshalling config: %v", err)
	}

	tests := []struct {
		module string
		got    int
		want   int
	}{
		{"http_tos", c.Modules["http_tos"].HTTP.TOS, 0x28},
		{"tcp_tos", c.Modules["tcp_tos"].TCP.TOS, 184},
		{"dns_tos", c.Modules["dns_tos"].DNS.TOS, 0x20},
		{"icmp_tos", c.Modules["icmp_tos"].ICMP.TOS, 255},
		{"icmp_default", c.Modules["icmp_default"].ICMP.TOS, 0},
	}
	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("module %s: got tos %d, want %d", test.module, test.got, test.want)
		}
	}
}
