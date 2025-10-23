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
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

func probeExpectInfo(registry *prometheus.Registry, qr *config.QueryResponse, bytes []byte, match []int) {
	var names []string
	var values []string
	for _, s := range qr.Labels {
		names = append(names, s.Name)
		values = append(values, string(qr.Expect.Expand(nil, []byte(s.Value), bytes, match)))
	}
	metric := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_expect_info",
			Help: "Explicit content matched",
		},
		names,
	)
	registry.MustRegister(metric)
	metric.WithLabelValues(values...).Set(1)
}

func probeQueryResponses(ctx context.Context, target string, conn net.Conn, module config.Module, proberName string, registry *prometheus.Registry, logger *slog.Logger) bool {
	probeSSLEarliestCertExpiry := prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)
	probeSSLLastChainExpiryTimestampSeconds := prometheus.NewGauge(sslChainExpiryInTimeStampGaugeOpts)
	probeSSLLastInformation := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_ssl_last_chain_info",
			Help: "Contains SSL leaf certificate information",
		},
		[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber"},
	)
	probeTLSVersion := prometheus.NewGaugeVec(
		probeTLSInfoGaugeOpts,
		[]string{"version"},
	)
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})
	registry.MustRegister(probeFailedDueToRegex)

	var queryResponses []config.QueryResponse
	var tlsConfig *pconfig.TLSConfig
	var useTLS bool

	switch proberName {
	case "tcp":
		queryResponses = module.TCP.QueryResponse
		tlsConfig = &module.TCP.TLSConfig
		useTLS = module.TCP.TLS
	case "unix":
		queryResponses = module.Unix.QueryResponse
		tlsConfig = &module.Unix.TLSConfig
		useTLS = module.Unix.TLS
	}

	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		logger.Error("Error setting deadline", "err", err)
		return false
	}

	if useTLS {
		state := conn.(*tls.Conn).ConnectionState()
		registry.MustRegister(probeSSLEarliestCertExpiry, probeTLSVersion, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
		probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).Unix()))
		probeTLSVersion.WithLabelValues(getTLSVersion(&state)).Set(1)
		probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(&state).Unix()))
		probeSSLLastInformation.WithLabelValues(getFingerprint(&state), getSubject(&state), getIssuer(&state), getDNSNames(&state), getSerialNumber(&state)).Set(1)
	}

	scanner := bufio.NewScanner(conn)
	for i, qr := range queryResponses {
		logger.Debug("Processing query response entry", "entry_number", i)
		send := qr.Send
		if qr.Expect.Regexp != nil {
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				logger.Debug("Read line", "line", scanner.Text())
				match = qr.Expect.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					logger.Debug("Regexp matched", "regexp", qr.Expect.Regexp, "line", scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				logger.Error("Error reading from connection", "err", scanner.Err().Error())
				return false
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				logger.Error("Regexp did not match", "regexp", qr.Expect.Regexp, "line", scanner.Text())
				return false
			}
			probeFailedDueToRegex.Set(0)
			send = string(qr.Expect.Expand(nil, []byte(send), scanner.Bytes(), match))
			if qr.Labels != nil {
				probeExpectInfo(registry, &qr, scanner.Bytes(), match)
			}
		}
		if send != "" {
			logger.Debug("Sending line", "line", send)
			if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
				logger.Error("Failed to send", "err", err)
				return false
			}
		}
		if qr.StartTLS {
			// Upgrade TCP connection to TLS.
			tlsUpgradeConfig, err := pconfig.NewTLSConfig(tlsConfig)
			if err != nil {
				logger.Error("Failed to create TLS configuration", "err", err)
				return false
			}
			if proberName == "tcp" && tlsUpgradeConfig.ServerName == "" {
				// Use target-hostname as default for TLS-servername.
				targetAddress, _, _ := net.SplitHostPort(target) // Had succeeded in dialTCP already.
				tlsUpgradeConfig.ServerName = targetAddress
			}

			tlsConn := tls.Client(conn, tlsUpgradeConfig)
			defer tlsConn.Close()

			// Initiate TLS handshake (required here to get TLS state).
			if err := tlsConn.Handshake(); err != nil {
				logger.Error("TLS Handshake (client) failed", "err", err)
				return false
			}
			logger.Debug("TLS Handshake (client) succeeded.")
			conn = net.Conn(tlsConn)
			scanner = bufio.NewScanner(conn)

			// Get certificate expiry.
			state := tlsConn.ConnectionState()
			registry.MustRegister(probeSSLEarliestCertExpiry, probeTLSVersion, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
			probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).Unix()))
			probeTLSVersion.WithLabelValues(getTLSVersion(&state)).Set(1)
			probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(&state).Unix()))
			probeSSLLastInformation.WithLabelValues(getFingerprint(&state), getSubject(&state), getIssuer(&state), getDNSNames(&state), getSerialNumber(&state)).Set(1)
		}
	}
	return true
}
