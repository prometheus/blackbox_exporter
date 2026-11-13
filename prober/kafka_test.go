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

package prober

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestParseKafkaTarget(t *testing.T) {
	got, err := parseKafkaTarget(" b1:9092, b2:9093 ,")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"b1:9092", "b2:9093"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, bad := range []string{"", ",", "b1", "b1:9092,b2"} {
		if _, err := parseKafkaTarget(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestKafkaSASLPassword(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(f, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		sasl *config.KafkaSASL
		want string
	}{
		{nil, ""},
		{&config.KafkaSASL{Password: "inline"}, "inline"},
		{&config.KafkaSASL{PasswordFile: f}, "from-file"},
	} {
		got, err := kafkaSASLPassword(tc.sasl)
		if err != nil || got != tc.want {
			t.Errorf("got %q, %v; want %q", got, err, tc.want)
		}
	}
	if _, err := kafkaSASLPassword(&config.KafkaSASL{PasswordFile: f + ".missing"}); err == nil {
		t.Error("expected error for missing password_file")
	}
}

// fakeKafkaMetadata registers a fetcher that returns md or err.
func fakeKafkaFetcher(t *testing.T, md *kafkaMetadata, err error) string {
	const name = "fake"
	kafkaFetchers[name] = func(context.Context, []string, config.KafkaProbe, string, *slog.Logger) (*kafkaMetadata, error) {
		return md, err
	}
	t.Cleanup(func() { delete(kafkaFetchers, name) })
	return name
}

func TestProbeKafka(t *testing.T) {
	md := &kafkaMetadata{
		ClusterID:    "abc",
		ControllerID: 2,
		Brokers:      []kafkaBroker{{ID: 1}, {ID: 2}, {ID: 3}},
		Topics: []kafkaTopic{
			{Name: "orders", Partitions: []kafkaPartition{
				{ID: 0, Leader: 1, Replicas: 3, ISR: 3},
				{ID: 1, Leader: -1, Replicas: 3, ISR: 0},
				{ID: 2, Leader: 2, Replicas: 3, ISR: 2},
			}},
			{Name: "unknown", Err: errors.New("unknown topic")},
		},
	}

	tests := []struct {
		name    string
		target  string
		cfg     config.KafkaProbe
		md      *kafkaMetadata
		err     error
		success bool
		metrics map[string]float64
	}{
		{
			name:    "ok",
			target:  "localhost:9092",
			md:      md,
			success: true,
			metrics: map[string]float64{
				"probe_kafka_brokers":                     3,
				"probe_kafka_topics":                      1,
				"probe_kafka_partitions":                  3,
				"probe_kafka_offline_partitions":          1,
				"probe_kafka_under_replicated_partitions": 2,
				"probe_kafka_controller_id":               2,
				"probe_kafka_cluster_info":                1,
			},
		},
		{
			name:    "topic ok",
			target:  "localhost:9092",
			cfg:     config.KafkaProbe{Topics: []string{"orders"}},
			md:      md,
			success: true,
			metrics: map[string]float64{"probe_kafka_topic_partitions": 3},
		},
		{
			name:    "topic with error",
			target:  "localhost:9092",
			cfg:     config.KafkaProbe{Topics: []string{"unknown"}},
			md:      md,
			metrics: map[string]float64{"probe_kafka_topic_partitions": 0},
		},
		{
			name:    "topic missing",
			target:  "localhost:9092",
			cfg:     config.KafkaProbe{Topics: []string{"missing"}},
			md:      md,
			metrics: map[string]float64{"probe_kafka_topic_partitions": 0},
		},
		{
			name:   "min brokers",
			target: "localhost:9092",
			cfg:    config.KafkaProbe{MinBrokers: 4},
			md:     md,
		},
		{
			name:   "fetch error",
			target: "localhost:9092",
			err:    errors.New("SASL authentication failed"),
		},
		{
			name:   "bad target",
			target: "localhost",
			md:     md,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.ClientLibrary = fakeKafkaFetcher(t, tc.md, tc.err)
			registry := prometheus.NewRegistry()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got := ProbeKafka(ctx, tc.target, config.Module{Kafka: tc.cfg}, registry, promslog.NewNopLogger())
			if got != tc.success {
				t.Fatalf("success = %v, want %v", got, tc.success)
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			checkRegistryResults(tc.metrics, mfs, t)
		})
	}
}

func TestProbeKafkaUnknownLibrary(t *testing.T) {
	module := config.Module{Kafka: config.KafkaProbe{ClientLibrary: "missing"}}
	if ProbeKafka(context.Background(), "localhost:9092", module, prometheus.NewRegistry(), promslog.NewNopLogger()) {
		t.Fatal("expected failure for unknown client library")
	}
}
