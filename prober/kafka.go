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
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/blackbox_exporter/config"
)

// kafkaMetadata is the client-library independent result of a metadata request.
type kafkaMetadata struct {
	ClusterID    string
	ControllerID int // -1 if unknown.
	Brokers      []kafkaBroker
	Topics       []kafkaTopic
}

type kafkaBroker struct {
	ID   int
	Host string
	Port int
}

type kafkaTopic struct {
	Name       string
	Err        error
	Partitions []kafkaPartition
}

type kafkaPartition struct {
	ID       int
	Leader   int // -1 if the partition has no leader.
	Replicas int
	ISR      int
	Err      error
}

// kafkaMetadataFetcher connects to the bootstrap servers, authenticates and
// returns the cluster metadata. It must honour the deadline of ctx.
type kafkaMetadataFetcher func(ctx context.Context, bootstrap []string, module config.KafkaProbe, password string, logger *slog.Logger) (*kafkaMetadata, error)

// kafkaFetchers holds the compiled-in client libraries.
var kafkaFetchers = map[string]kafkaMetadataFetcher{
	config.KafkaClientSegmentio: fetchKafkaMetadataSegmentio,
}

// parseKafkaTarget splits a comma-separated list of host:port bootstrap servers.
func parseKafkaTarget(target string) ([]string, error) {
	var servers []string
	for s := range strings.SplitSeq(target, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			return nil, fmt.Errorf("invalid bootstrap server %q: %w", s, err)
		}
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		return nil, errors.New("no bootstrap server in target")
	}
	return servers, nil
}

func kafkaSASLPassword(sasl *config.KafkaSASL) (string, error) {
	if sasl == nil {
		return "", nil
	}
	if sasl.PasswordFile != "" {
		b, err := os.ReadFile(sasl.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("unable to read sasl password_file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return string(sasl.Password), nil
}

func ProbeKafka(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) bool {
	var (
		durationGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_kafka_metadata_duration_seconds",
			Help: "Duration of connect, authentication and metadata request in seconds",
		})
		brokersGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_kafka_brokers",
			Help: "Number of brokers in the cluster metadata",
		})
		topicsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_kafka_topics",
			Help: "Number of topics in the cluster metadata",
		})
		partitionsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_kafka_partitions",
			Help: "Number of partitions in the cluster metadata",
		})
		offlineGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_kafka_offline_partitions",
			Help: "Number of partitions without a leader",
		})
		underReplicatedGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_kafka_under_replicated_partitions",
			Help: "Number of partitions with fewer in-sync replicas than replicas",
		})
		controllerGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_kafka_controller_id",
			Help: "Broker ID of the active controller, -1 if unknown",
		})
		clusterInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_kafka_cluster_info",
			Help: "Cluster information, value is always 1",
		}, []string{"cluster_id", "client_library"})
		topicPartitions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_kafka_topic_partitions",
			Help: "Number of partitions of a configured topic, 0 if the topic is missing or has an error",
		}, []string{"topic"})
	)
	registry.MustRegister(durationGauge)

	cfg := module.Kafka
	fetch, ok := kafkaFetchers[cfg.ClientLibrary]
	if !ok {
		logger.Error("Kafka client library is not available in this build", "client_library", cfg.ClientLibrary)
		return false
	}

	bootstrap, err := parseKafkaTarget(target)
	if err != nil {
		logger.Error("Error parsing target", "err", err)
		return false
	}

	password, err := kafkaSASLPassword(cfg.SASL)
	if err != nil {
		logger.Error("Error reading SASL password", "err", err)
		return false
	}

	logger.Debug("Requesting Kafka metadata", "bootstrap", bootstrap, "client_library", cfg.ClientLibrary)
	start := time.Now()
	md, err := fetch(ctx, bootstrap, cfg, password, logger)
	durationGauge.Set(time.Since(start).Seconds())
	if err != nil {
		logger.Error("Error requesting Kafka metadata", "err", err)
		return false
	}

	registry.MustRegister(brokersGauge, topicsGauge, partitionsGauge, offlineGauge,
		underReplicatedGauge, controllerGauge, clusterInfo)

	// Requested topics that do not exist come back with an error and are not counted.
	var topics, partitions, offline, underReplicated int
	for _, t := range md.Topics {
		if t.Err == nil {
			topics++
		}
		for _, p := range t.Partitions {
			partitions++
			if p.Leader < 0 {
				offline++
			}
			if p.ISR < p.Replicas {
				underReplicated++
			}
		}
	}
	brokersGauge.Set(float64(len(md.Brokers)))
	topicsGauge.Set(float64(topics))
	partitionsGauge.Set(float64(partitions))
	offlineGauge.Set(float64(offline))
	underReplicatedGauge.Set(float64(underReplicated))
	controllerGauge.Set(float64(md.ControllerID))
	clusterInfo.WithLabelValues(md.ClusterID, cfg.ClientLibrary).Set(1)
	logger.Debug("Received Kafka metadata", "cluster_id", md.ClusterID, "controller_id", md.ControllerID,
		"brokers", len(md.Brokers), "topics", topics, "partitions", partitions)

	success := true
	if len(md.Brokers) < cfg.MinBrokers {
		logger.Error("Cluster has fewer brokers than min_brokers", "brokers", len(md.Brokers), "min_brokers", cfg.MinBrokers)
		success = false
	}

	if len(cfg.Topics) > 0 {
		registry.MustRegister(topicPartitions)
		found := make(map[string]kafkaTopic, len(md.Topics))
		for _, t := range md.Topics {
			found[t.Name] = t
		}
		for _, name := range cfg.Topics {
			t, ok := found[name]
			switch {
			case !ok:
				logger.Error("Topic not found in metadata", "topic", name)
				topicPartitions.WithLabelValues(name).Set(0)
				success = false
			case t.Err != nil:
				logger.Error("Topic has an error in metadata", "topic", name, "err", t.Err)
				topicPartitions.WithLabelValues(name).Set(0)
				success = false
			default:
				topicPartitions.WithLabelValues(name).Set(float64(len(t.Partitions)))
			}
		}
	}
	return success
}
