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
	"fmt"
	"log/slog"

	pconfig "github.com/prometheus/common/config"
	"github.com/segmentio/kafka-go"
	metadataAPI "github.com/segmentio/kafka-go/protocol/metadata"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/prometheus/blackbox_exporter/config"
)

func segmentioSASLMechanism(s *config.KafkaSASL, password string) (sasl.Mechanism, error) {
	if s == nil {
		return nil, nil
	}
	switch s.Mechanism {
	case config.KafkaSASLPlain:
		return plain.Mechanism{Username: s.Username, Password: password}, nil
	case config.KafkaSASLScramSHA256:
		return scram.Mechanism(scram.SHA256, s.Username, password)
	case config.KafkaSASLScramSHA512:
		return scram.Mechanism(scram.SHA512, s.Username, password)
	default:
		return nil, fmt.Errorf("unsupported sasl mechanism %q", s.Mechanism)
	}
}

func fetchKafkaMetadataSegmentio(ctx context.Context, bootstrap []string, cfg config.KafkaProbe, password string, _ *slog.Logger) (*kafkaMetadata, error) {
	mechanism, err := segmentioSASLMechanism(cfg.SASL, password)
	if err != nil {
		return nil, err
	}

	transport := &kafka.Transport{
		ClientID:       cfg.ClientID,
		SASL:           mechanism,
		MetadataTopics: cfg.Topics,
	}
	if cfg.TLS {
		// An empty ServerName is set to the broker host by kafka-go.
		transport.TLS, err = pconfig.NewTLSConfig(&cfg.TLSConfig)
		if err != nil {
			return nil, fmt.Errorf("error creating TLS configuration: %w", err)
		}
	}
	defer transport.CloseIdleConnections()

	// Use the raw protocol message: the high-level kafka.Client.Metadata maps
	// a missing partition leader (-1) to broker ID 0.
	msg, err := transport.RoundTrip(ctx, kafka.TCP(bootstrap...), &metadataAPI.Request{TopicNames: cfg.Topics})
	if err != nil {
		return nil, err
	}
	res, ok := msg.(*metadataAPI.Response)
	if !ok {
		return nil, fmt.Errorf("unexpected metadata response type %T", msg)
	}

	md := &kafkaMetadata{
		ClusterID:    res.ClusterID,
		ControllerID: int(res.ControllerID),
		Brokers:      make([]kafkaBroker, 0, len(res.Brokers)),
		Topics:       make([]kafkaTopic, 0, len(res.Topics)),
	}
	for _, b := range res.Brokers {
		md.Brokers = append(md.Brokers, kafkaBroker{ID: int(b.NodeID), Host: b.Host, Port: int(b.Port)})
	}
	for _, t := range res.Topics {
		topic := kafkaTopic{Name: t.Name, Err: segmentioError(t.ErrorCode)}
		for _, p := range t.Partitions {
			topic.Partitions = append(topic.Partitions, kafkaPartition{
				ID:       int(p.PartitionIndex),
				Leader:   int(p.LeaderID),
				Replicas: len(p.ReplicaNodes),
				ISR:      len(p.IsrNodes),
				Err:      segmentioError(p.ErrorCode),
			})
		}
		md.Topics = append(md.Topics, topic)
	}
	return md, nil
}

func segmentioError(code int16) error {
	if code == 0 {
		return nil
	}
	return kafka.Error(code)
}
