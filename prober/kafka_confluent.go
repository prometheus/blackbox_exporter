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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"

	"github.com/prometheus/blackbox_exporter/config"
)

// confluentCacheLookupTimeout bounds the lookup of cluster ID and controller
// ID in the librdkafka metadata cache.
const (
	confluentCacheLookupTimeout = 100 * time.Millisecond
	// confluentConnectSlice is shorter than the smallest reconnect backoff
	// of librdkafka (reconnect.backoff.ms 100 ms minus 25 % jitter).
	confluentConnectSlice = 50 * time.Millisecond
	// confluentDefaultTimeout applies if the probe context has no deadline.
	confluentDefaultTimeout = 10 * time.Second
)

func init() {
	kafkaFetchers[config.KafkaClientConfluent] = fetchKafkaMetadataConfluent
}

// confluentConfigMap maps the module configuration to librdkafka properties.
func confluentConfigMap(bootstrap []string, cfg config.KafkaProbe, password string) (kafka.ConfigMap, error) {
	cm := kafka.ConfigMap{
		"bootstrap.servers":        strings.Join(bootstrap, ","),
		"allow.auto.create.topics": false,
		// The Go client allocates both channels at once. The defaults
		// (1000000 each) cost about 24 MB per probe; the probe produces nothing.
		"go.events.channel.size":  100,
		"go.produce.channel.size": 1,
		"go.delivery.reports":     false,
	}
	if cfg.ClientID != "" {
		cm["client.id"] = cfg.ClientID
	}

	protocol := "plaintext"
	if cfg.SASL != nil {
		protocol = "sasl_plaintext"
		cm["sasl.mechanisms"] = cfg.SASL.Mechanism
		cm["sasl.username"] = cfg.SASL.Username
		cm["sasl.password"] = password
	}
	if cfg.TLS {
		if cfg.SASL != nil {
			protocol = "sasl_ssl"
		} else {
			protocol = "ssl"
		}
		t := cfg.TLSConfig
		set := func(key, value string) {
			if value != "" {
				cm[key] = value
			}
		}
		set("ssl.ca.location", t.CAFile)
		set("ssl.ca.pem", t.CA)
		set("ssl.certificate.location", t.CertFile)
		set("ssl.certificate.pem", t.Cert)
		set("ssl.key.location", t.KeyFile)
		set("ssl.key.pem", string(t.Key))
		if t.InsecureSkipVerify {
			cm["enable.ssl.certificate.verification"] = false
			cm["ssl.endpoint.identification.algorithm"] = "none"
		}
	}
	cm["security.protocol"] = protocol

	for k, v := range cfg.LibrdkafkaConfig {
		if err := cm.SetKey(k, v); err != nil {
			return nil, fmt.Errorf("invalid librdkafka_config %q: %w", k, err)
		}
	}
	return cm, nil
}

func fetchKafkaMetadataConfluent(ctx context.Context, bootstrap []string, cfg config.KafkaProbe, password string, logger *slog.Logger) (*kafkaMetadata, error) {
	cm, err := confluentConfigMap(bootstrap, cfg, password)
	if err != nil {
		return nil, err
	}
	// Forward librdkafka logs to the probe logger instead of stderr.
	logs := make(chan kafka.LogEvent, 1000)
	cm["go.logs.channel.enable"] = true
	cm["go.logs.channel"] = logs

	// A producer is the lightest librdkafka handle: no group membership, and
	// its Events() channel reports connection and authentication errors.
	p, err := kafka.NewProducer(&cm)
	if err != nil {
		return nil, fmt.Errorf("error creating librdkafka client: %w", err)
	}

	closed := make(chan struct{})
	go func() {
		for {
			select {
			case l := <-logs:
				logger.Debug("librdkafka", "tag", l.Tag, "level", l.Level, "message", l.Message)
			case <-closed:
				return
			}
		}
	}()

	// librdkafka retries internally until the request timeout. Report
	// authentication failures and unreachable brokers at once.
	fatal := make(chan error, 1)
	go func() {
		var last error // Cause of "all brokers down", e.g. a TLS error.
		for ev := range p.Events() {
			e, ok := ev.(kafka.Error)
			if !ok {
				continue
			}
			logger.Debug("librdkafka error event", "code", e.Code(), "err", e)
			var err error
			switch {
			case e.Code() == kafka.ErrAllBrokersDown && last != nil:
				err = fmt.Errorf("%w (last error: %v)", e, last)
			case e.Code() == kafka.ErrAuthentication || e.Code() == kafka.ErrAllBrokersDown || e.IsFatal():
				err = e
			default:
				last = e
				continue
			}
			select {
			case fatal <- err:
			default:
			}
		}
	}()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(confluentDefaultTimeout)
	}

	type result struct {
		md  *kafkaMetadata
		err error
	}
	resCh := make(chan result, 1)
	stop := make(chan struct{})
	// The librdkafka calls are not context aware. This goroutine owns the
	// handle and closes it, also when the probe has already returned.
	go func() {
		md, err := confluentQuery(p, cfg, deadline, stop, logger)
		resCh <- result{md, err}
		p.Close()
		close(closed)
	}()

	select {
	case r := <-resCh:
		return r.md, r.err
	case err = <-fatal:
	case <-ctx.Done():
		err = ctx.Err()
	}
	close(stop)
	// Prefer a result that arrived at the same time.
	select {
	case r := <-resCh:
		if r.err == nil {
			return r.md, nil
		}
	default:
	}
	return nil, err
}

// confluentGetMetadata requests metadata for one topic, or for all topics if
// topic is nil. GetMetadata blocks until its timeout while no broker is
// usable, and it cannot be cancelled. Thus call it in short slices until a
// broker is up: after a failure (stop is closed) the handle is then released
// before librdkafka reconnects and, for example, sends a wrong password again.
func confluentGetMetadata(p *kafka.Producer, topic *string, deadline time.Time, stop <-chan struct{}) (*kafka.Metadata, error) {
	slice := confluentConnectSlice
	for {
		remaining := max(time.Until(deadline), time.Millisecond)
		md, err := p.GetMetadata(topic, topic == nil, int(min(slice, remaining).Milliseconds()))
		if err == nil {
			return md, nil
		}
		select {
		case <-stop:
			return nil, err
		default:
		}
		var kerr kafka.Error
		if !errors.As(err, &kerr) || remaining <= slice {
			return nil, err
		}
		switch kerr.Code() {
		case kafka.ErrTransport:
			// No usable broker yet, no request was sent.
		case kafka.ErrTimedOut:
			// A broker is up but the response is slow: wait for the full time.
			slice = remaining
		default:
			return nil, err
		}
	}
}

func confluentQuery(p *kafka.Producer, cfg config.KafkaProbe, deadline time.Time, stop <-chan struct{}, logger *slog.Logger) (*kafkaMetadata, error) {
	md := &kafkaMetadata{ControllerID: -1}
	add := func(raw *kafka.Metadata) {
		if md.Brokers == nil {
			for _, b := range raw.Brokers {
				md.Brokers = append(md.Brokers, kafkaBroker{ID: int(b.ID), Host: b.Host, Port: b.Port})
			}
		}
		for _, t := range raw.Topics {
			topic := kafkaTopic{Name: t.Topic, Err: confluentError(t.Error)}
			for _, part := range t.Partitions {
				topic.Partitions = append(topic.Partitions, kafkaPartition{
					ID:       int(part.ID),
					Leader:   int(part.Leader),
					Replicas: len(part.Replicas),
					ISR:      len(part.Isrs),
					Err:      confluentError(part.Error),
				})
			}
			md.Topics = append(md.Topics, topic)
		}
	}

	if len(cfg.Topics) == 0 {
		raw, err := confluentGetMetadata(p, nil, deadline, stop)
		if err != nil {
			return nil, err
		}
		add(raw)
	}
	// librdkafka accepts one topic or all topics. Do not load all topics of
	// a large cluster to examine some of them.
	for i := range cfg.Topics {
		raw, err := confluentGetMetadata(p, &cfg.Topics[i], deadline, stop)
		if err != nil {
			return nil, err
		}
		add(raw)
	}

	// GetMetadata does not return cluster ID and controller, but librdkafka
	// caches both from its own metadata requests. Read them from that cache
	// with a short timeout: if they are not there now, they will not come
	// (for example very old brokers). A failure here is not fatal.
	admin, err := kafka.NewAdminClientFromProducer(p)
	if err != nil {
		logger.Debug("Error creating admin client", "err", err)
		return md, nil
	}
	defer admin.Close()
	cacheCtx, cancel := context.WithTimeout(context.Background(), confluentCacheLookupTimeout)
	defer cancel()
	if id, err := admin.ClusterID(cacheCtx); err == nil {
		md.ClusterID = id
	} else {
		logger.Debug("Cluster ID not known", "err", err)
	}
	if id, err := admin.ControllerID(cacheCtx); err == nil {
		md.ControllerID = int(id)
	} else {
		logger.Debug("Controller ID not known", "err", err)
	}
	return md, nil
}

func confluentError(e kafka.Error) error {
	if e.Code() == kafka.ErrNoError {
		return nil
	}
	return e
}
