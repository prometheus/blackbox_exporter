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

package config

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestKafkaProbeConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:  "defaults",
			input: "prober: kafka\n",
		},
		{
			name: "sasl scram",
			input: `prober: kafka
kafka:
  tls: true
  sasl: {mechanism: scram-sha-512, username: bob, password: secret}
  topics: [orders]
  min_brokers: 3
`,
		},
		{
			name:    "invalid library",
			input:   "prober: kafka\nkafka: {client_library: sarama}\n",
			wantErr: "client_library \"sarama\" is not valid",
		},
		{
			name:    "librdkafka_config with segmentio",
			input:   "prober: kafka\nkafka: {librdkafka_config: {debug: all}}\n",
			wantErr: "librdkafka_config can only be used",
		},
		{
			name:    "invalid mechanism",
			input:   "prober: kafka\nkafka: {sasl: {mechanism: GSSAPI, username: a, password: b}}\n",
			wantErr: "sasl mechanism \"GSSAPI\" is not valid",
		},
		{
			name:    "missing username",
			input:   "prober: kafka\nkafka: {sasl: {mechanism: PLAIN, password: b}}\n",
			wantErr: "username must be set",
		},
		{
			name:    "missing password",
			input:   "prober: kafka\nkafka: {sasl: {mechanism: PLAIN, username: a}}\n",
			wantErr: "password or password_file must be set",
		},
		{
			name:    "password and password_file",
			input:   "prober: kafka\nkafka: {sasl: {mechanism: PLAIN, username: a, password: b, password_file: /x}}\n",
			wantErr: "mutually exclusive",
		},
		{
			name:    "negative min_brokers",
			input:   "prober: kafka\nkafka: {min_brokers: -1}\n",
			wantErr: "min_brokers must not be negative",
		},
		{
			name:    "empty topic",
			input:   "prober: kafka\nkafka: {topics: [\"\"]}\n",
			wantErr: "empty names",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var m Module
			err := yaml.Unmarshal([]byte(tc.input), &m)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if m.Kafka.ClientLibrary != KafkaClientSegmentio {
					t.Fatalf("expected default client_library %q, got %q", KafkaClientSegmentio, m.Kafka.ClientLibrary)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestKafkaConfluentAvailability(t *testing.T) {
	var m Module
	err := yaml.Unmarshal([]byte("prober: kafka\nkafka: {client_library: confluent}\n"), &m)
	if kafkaConfluentAvailable && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !kafkaConfluentAvailable && (err == nil || !strings.Contains(err.Error(), "not available")) {
		t.Fatalf("expected 'not available' error, got %v", err)
	}
}
