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
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

func TestLoadConfig(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}

	err := sc.ReloadConfig("testdata/blackbox-good.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "blackbox.yml", err)
	}
}

func TestLoadBadConfigs(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "testdata/blackbox-bad.yml",
			want:  "error parsing config file: yaml: unmarshal errors:\n  line 50: field invalid_extra_field not found in type config.plain",
		},
		{
			input: "testdata/blackbox-bad2.yml",
			want:  "error parsing config file: at most one of bearer_token & bearer_token_file must be configured",
		},
		{
			input: "testdata/invalid-dns-module.yml",
			want:  "error parsing config file: query name must be set for DNS module",
		},
		{
			input: "testdata/invalid-dns-class.yml",
			want:  "error parsing config file: query class 'X' is not valid",
		},
		{
			input: "testdata/invalid-dns-type.yml",
			want:  "error parsing config file: query type 'X' is not valid",
		},
		{
			input: "testdata/invalid-http-header-match.yml",
			want:  "error parsing config file: regexp must be set for HTTP header matchers",
		},
		{
			input: "testdata/invalid-http-body-match-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-http-body-not-match-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-http-header-match-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-tcp-query-response-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got := sc.ReloadConfig(test.input)
			if got == nil || got.Error() != test.want {
				t.Fatalf("ReloadConfig(%q) = %v; want %q", test.input, got, test.want)
			}
		})
	}
}

func TestHideConfigSecrets(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}

	err := sc.ReloadConfig("testdata/blackbox-good.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/blackbox-good.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshalling config: %v", err)
	}
	if strings.Contains(string(c), "mysecret") {
		t.Fatal("config's String method reveals authentication credentials.")
	}
}
