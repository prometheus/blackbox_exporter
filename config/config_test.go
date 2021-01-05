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
		ConfigFile    string
		ExpectedError string
	}{
		{
			ConfigFile:    "testdata/blackbox-bad.yml",
			ExpectedError: "error parsing config file: yaml: unmarshal errors:\n  line 50: field invalid_extra_field not found in type config.plain",
		},
		{
			ConfigFile:    "testdata/blackbox-bad2.yml",
			ExpectedError: "error parsing config file: at most one of bearer_token & bearer_token_file must be configured",
		},
		{
			ConfigFile:    "testdata/invalid-dns-module.yml",
			ExpectedError: "error parsing config file: query name must be set for DNS module",
		},
		{
			ConfigFile:    "testdata/invalid-dns-class.yml",
			ExpectedError: "error parsing config file: query class 'X' is not valid",
		},
		{
			ConfigFile:    "testdata/invalid-dns-type.yml",
			ExpectedError: "error parsing config file: query type 'X' is not valid",
		},
		{
			ConfigFile:    "testdata/invalid-http-header-match.yml",
			ExpectedError: "error parsing config file: regexp must be set for HTTP header matchers",
		},
		{
			ConfigFile:    "testdata/invalid-http-body-match-regexp.yml",
			ExpectedError: "error parsing config file: \"Could not compile regular expression\" regexp=\":[\"",
		},
		{
			ConfigFile:    "testdata/invalid-http-body-not-match-regexp.yml",
			ExpectedError: "error parsing config file: \"Could not compile regular expression\" regexp=\":[\"",
		},
		{
			ConfigFile:    "testdata/invalid-http-header-match-regexp.yml",
			ExpectedError: "error parsing config file: \"Could not compile regular expression\" regexp=\":[\"",
		},
		{
			ConfigFile:    "testdata/invalid-tcp-query-response-regexp.yml",
			ExpectedError: "error parsing config file: \"Could not compile regular expression\" regexp=\":[\"",
		},
	}
	for i, test := range tests {
		err := sc.ReloadConfig(test.ConfigFile)
		if err == nil {
			t.Errorf("In case %v:\nExpected:\n%v\nGot:\nnil", i, test.ExpectedError)
			continue
		}
		if err.Error() != test.ExpectedError {
			t.Errorf("In case %v:\nExpected:\n%v\nGot:\n%v", i, test.ExpectedError, err.Error())
		}
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
