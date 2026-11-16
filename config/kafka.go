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
	"errors"
	"fmt"
	"strings"

	"github.com/prometheus/common/config"
)

const (
	// KafkaClientSegmentio selects github.com/segmentio/kafka-go (pure Go).
	KafkaClientSegmentio = "segmentio"
	// KafkaClientConfluent selects github.com/confluentinc/confluent-kafka-go
	// (librdkafka, needs a CGO build with the "confluent" build tag).
	KafkaClientConfluent = "confluent"

	KafkaSASLPlain       = "PLAIN"
	KafkaSASLScramSHA256 = "SCRAM-SHA-256"
	KafkaSASLScramSHA512 = "SCRAM-SHA-512"
)

// KafkaProbe configures the kafka prober. The prober connects to the
// bootstrap server(s) given as target, authenticates and requests the
// cluster metadata.
type KafkaProbe struct {
	// ClientLibrary is "segmentio" (default) or "confluent".
	ClientLibrary string `yaml:"client_library,omitempty" json:"client_library,omitempty"`
	ClientID      string `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	// TLS enables TLS (security.protocol SSL or SASL_SSL).
	TLS       bool             `yaml:"tls,omitempty" json:"tls,omitempty"`
	TLSConfig config.TLSConfig `yaml:"tls_config,omitempty" json:"tls_config,omitzero"`
	// SASL enables SASL authentication when set.
	SASL *KafkaSASL `yaml:"sasl,omitempty" json:"sasl,omitempty"`
	// Topics limits the metadata request to these topics. The probe fails
	// if one of them does not exist or reports an error. Empty means all topics.
	Topics []string `yaml:"topics,omitempty" json:"topics,omitempty"`
	// MinBrokers makes the probe fail if the cluster reports fewer brokers.
	MinBrokers int `yaml:"min_brokers,omitempty" json:"min_brokers,omitempty"`
	// LibrdkafkaConfig sets additional librdkafka properties. Only for the
	// confluent client library. These values override the generated ones.
	LibrdkafkaConfig map[string]string `yaml:"librdkafka_config,omitempty" json:"librdkafka_config,omitempty"`
}

// KafkaSASL configures SASL authentication.
type KafkaSASL struct {
	// Mechanism is PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512.
	Mechanism    string        `yaml:"mechanism,omitempty" json:"mechanism,omitempty"`
	Username     string        `yaml:"username,omitempty" json:"username,omitempty"`
	Password     config.Secret `yaml:"password,omitempty" json:"password,omitempty"`
	PasswordFile string        `yaml:"password_file,omitempty" json:"password_file,omitempty"`
}

// kafkaConfluentAvailable is true when the binary is built with the
// confluent client library (see kafka_confluent.go).
var kafkaConfluentAvailable = false

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *KafkaProbe) UnmarshalYAML(unmarshal func(any) error) error {
	*s = DefaultKafkaProbe
	type plain KafkaProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	switch s.ClientLibrary {
	case KafkaClientSegmentio:
		if len(s.LibrdkafkaConfig) > 0 {
			return errors.New("librdkafka_config can only be used with client_library \"confluent\"")
		}
	case KafkaClientConfluent:
		if !kafkaConfluentAvailable {
			return errors.New("client_library \"confluent\" is not available: build with CGO_ENABLED=1 and -tags confluent")
		}
		t := s.TLSConfig
		if t.ServerName != "" || t.CARef != "" || t.CertRef != "" || t.KeyRef != "" || t.MinVersion != 0 || t.MaxVersion != 0 {
			return errors.New("tls_config server_name, *_ref, min_version and max_version are not supported with client_library \"confluent\"; use librdkafka_config")
		}
	default:
		return fmt.Errorf("kafka client_library %q is not valid, use %q or %q", s.ClientLibrary, KafkaClientSegmentio, KafkaClientConfluent)
	}

	if s.MinBrokers < 0 {
		return errors.New("min_brokers must not be negative")
	}
	for _, t := range s.Topics {
		if strings.TrimSpace(t) == "" {
			return errors.New("topics must not contain empty names")
		}
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *KafkaSASL) UnmarshalYAML(unmarshal func(any) error) error {
	type plain KafkaSASL
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	s.Mechanism = strings.ToUpper(s.Mechanism)
	switch s.Mechanism {
	case KafkaSASLPlain, KafkaSASLScramSHA256, KafkaSASLScramSHA512:
	default:
		return fmt.Errorf("kafka sasl mechanism %q is not valid, use %s, %s or %s", s.Mechanism, KafkaSASLPlain, KafkaSASLScramSHA256, KafkaSASLScramSHA512)
	}
	if s.Username == "" {
		return errors.New("kafka sasl username must be set")
	}
	if s.Password != "" && s.PasswordFile != "" {
		return errors.New("kafka sasl password and password_file are mutually exclusive")
	}
	if s.Password == "" && s.PasswordFile == "" {
		return errors.New("kafka sasl password or password_file must be set")
	}
	return nil
}
