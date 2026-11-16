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

//go:build confluent && cgo

package prober

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

// TestProbeKafkaMockCluster runs both client libraries against the
// librdkafka mock cluster (a real Kafka protocol server in-process).
func TestProbeKafkaMockCluster(t *testing.T) {
	mc, err := kafka.NewMockCluster(3)
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Close()
	if err := mc.CreateTopic("orders", 6, 3); err != nil {
		t.Fatal(err)
	}
	if err := mc.CreateTopic("payments", 2, 3); err != nil {
		t.Fatal(err)
	}

	// Find a closed port for the failure case.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := l.Addr().String()
	l.Close()

	for _, lib := range []string{config.KafkaClientSegmentio, config.KafkaClientConfluent} {
		t.Run(lib, func(t *testing.T) {
			// All topics.
			all := config.Module{Kafka: config.KafkaProbe{ClientLibrary: lib}}
			allRegistry := prometheus.NewRegistry()
			allCtx, allCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer allCancel()
			if !ProbeKafka(allCtx, mc.BootstrapServers(), all, allRegistry, promslog.NewNopLogger()) {
				t.Fatal("probe for all topics failed")
			}
			allMfs, err := allRegistry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			checkRegistryResults(map[string]float64{
				"probe_kafka_brokers":    3,
				"probe_kafka_topics":     2,
				"probe_kafka_partitions": 8,
			}, allMfs, t)

			// A missing topic fails the probe.
			missing := config.Module{Kafka: config.KafkaProbe{ClientLibrary: lib, Topics: []string{"orders", "missing"}}}
			missingCtx, missingCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer missingCancel()
			if ProbeKafka(missingCtx, mc.BootstrapServers(), missing, prometheus.NewRegistry(), promslog.NewNopLogger()) {
				t.Fatal("probe with a missing topic succeeded")
			}

			module := config.Module{Kafka: config.KafkaProbe{ClientLibrary: lib, Topics: []string{"orders", "payments"}, MinBrokers: 3}}
			registry := prometheus.NewRegistry()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			probeStart := time.Now()
			if !ProbeKafka(ctx, mc.BootstrapServers(), module, registry, promslog.NewNopLogger()) {
				t.Fatal("probe failed")
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			checkRegistryResults(map[string]float64{
				"probe_kafka_brokers":            3,
				"probe_kafka_topics":             2,
				"probe_kafka_partitions":         8,
				"probe_kafka_offline_partitions": 0,
			}, mfs, t)
			if d := time.Since(probeStart); d > 2*time.Second {
				t.Errorf("successful probe took %v", d)
			}

			start := time.Now()
			ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel2()
			if ProbeKafka(ctx2, closedAddr, module, prometheus.NewRegistry(), promslog.NewNopLogger()) {
				t.Fatal("probe against closed port succeeded")
			}
			if d := time.Since(start); d > 4*time.Second {
				t.Errorf("probe against closed port took %v, expected fast failure", d)
			}
		})
	}
}

func TestConfluentConfigMap(t *testing.T) {
	sasl := &config.KafkaSASL{Mechanism: config.KafkaSASLScramSHA512, Username: "bob"}
	tests := []struct {
		name string
		cfg  config.KafkaProbe
		want map[string]kafka.ConfigValue
	}{
		{"plaintext", config.KafkaProbe{}, map[string]kafka.ConfigValue{"security.protocol": "plaintext", "bootstrap.servers": "a:1,b:2", "allow.auto.create.topics": false}},
		{"ssl", config.KafkaProbe{TLS: true}, map[string]kafka.ConfigValue{"security.protocol": "ssl"}},
		{"sasl_plaintext", config.KafkaProbe{SASL: sasl}, map[string]kafka.ConfigValue{
			"security.protocol": "sasl_plaintext", "sasl.mechanisms": "SCRAM-SHA-512", "sasl.username": "bob", "sasl.password": "pw",
		}},
		{"sasl_ssl", config.KafkaProbe{TLS: true, SASL: sasl, ClientID: "id"}, map[string]kafka.ConfigValue{"security.protocol": "sasl_ssl", "client.id": "id"}},
		{"insecure", config.KafkaProbe{TLS: true, TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: true, CAFile: "/ca"}}, map[string]kafka.ConfigValue{
			"enable.ssl.certificate.verification": false, "ssl.endpoint.identification.algorithm": "none", "ssl.ca.location": "/ca",
		}},
		{"override", config.KafkaProbe{LibrdkafkaConfig: map[string]string{"security.protocol": "ssl", "debug": "broker"}}, map[string]kafka.ConfigValue{
			"security.protocol": "ssl", "debug": "broker",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm, err := confluentConfigMap([]string{"a:1", "b:2"}, tc.cfg, "pw")
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tc.want {
				if cm[k] != v {
					t.Errorf("%s = %v, want %v", k, cm[k], v)
				}
			}
			if !tc.cfg.TLS {
				if _, ok := cm["ssl.ca.location"]; ok {
					t.Error("TLS properties set without tls")
				}
			}
		})
	}
}
