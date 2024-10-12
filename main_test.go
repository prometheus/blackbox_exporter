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
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"testing"
)

func TestComputeExternalURL(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{
			input: "",
			valid: true,
		},
		{
			input: "http://proxy.com/prometheus",
			valid: true,
		},
		{
			input: "'https://url/prometheus'",
			valid: false,
		},
		{
			input: "'relative/path/with/quotes'",
			valid: false,
		},
		{
			input: "http://alertmanager.company.com",
			valid: true,
		},
		{
			input: "https://double--dash.de",
			valid: true,
		},
		{
			input: "'http://starts/with/quote",
			valid: false,
		},
		{
			input: "ends/with/quote\"",
			valid: false,
		},
	}

	for _, test := range tests {
		_, err := computeExternalURL(test.input, "0.0.0.0:9090")
		if test.valid {
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}
		} else {
			if err == nil {
				t.Errorf("expected error computing %s got none", test.input)
			}
		}
	}
}

func TestInvalidConfigCheck(t *testing.T) {
	sc := config.NewSafeConfig(prometheus.NewRegistry())

	err := sc.ReloadConfig("config/testdata/invalid-probe-type-config.yml", nil)
	if err != nil {
		t.Fatal("Invalid config file 'config/testdata/invalid-probe-type-config.yml'")
	}

	err = checkModuleProbeType(sc, nil)
	if err == nil {
		t.Errorf("Error: test should fail")
	}
}
