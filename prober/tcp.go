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

func dialTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (net.Conn, ProbeResult) {
	var dialProtocol, dialTarget string
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		logger.Error(err.Error())
		return nil, ProbeFailure("Error splitting target address and port")
	}

	ip, _, resolveResult := chooseProtocol(ctx, module.TCP.IPProtocol, module.TCP.IPProtocolFallback, targetAddress, registry, logger)
	if !resolveResult.success {
		return nil, resolveResult
	}

	if ip.IP.To4() == nil {
		dialProtocol = "tcp6"
	} else {
		dialProtocol = "tcp4"
	}

	if len(module.TCP.SourceIPAddress) > 0 {
		srcIP := net.ParseIP(module.TCP.SourceIPAddress)
		if srcIP == nil {
			logger.Error("Error parsing source ip address", "srcIP", module.TCP.SourceIPAddress)
			return nil, ProbeFailure("error parsing source ip address")
		}
		logger.Info("Using local address", "srcIP", srcIP)
		dialer.LocalAddr = &net.TCPAddr{IP: srcIP}
	}

	dialTarget = net.JoinHostPort(ip.String(), port)

	if !module.TCP.TLS {
		logger.Info("Dialing TCP without TLS")
		conn, err := dialer.DialContext(ctx, dialProtocol, dialTarget)
		if err != nil {
			logger.Error("Dialing TCP without TLS failed", "err", err)
			return nil, ProbeFailure("Dialing TCP failed", "tls", "false")
		}

		return conn, ProbeSuccess()
	}
	tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
	if err != nil {
		logger.Error("Error creating TLS configuration", "err", err)
		return nil, ProbeFailure("Error creating TLS configuration")
	}

	if len(tlsConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// targetAddress as TLS-servername. Normally tls.DialWithDialer
		// would do this for us, but we pre-resolved the name by
		// `chooseProtocol` and pass the IP-address for dialing (prevents
		// resolving twice).
		// For this reason we need to specify the original targetAddress
		// via tlsConfig to enable hostname verification.
		tlsConfig.ServerName = targetAddress
	}
	timeoutDeadline, _ := ctx.Deadline()
	dialer.Deadline = timeoutDeadline

	logger.Info("Dialing TCP with TLS")
	conn, err := tls.DialWithDialer(dialer, dialProtocol, dialTarget, tlsConfig)
	if err != nil {
		logger.Error("Dialing TCP with TLS failed", "err", err)
		return nil, ProbeFailure("Dialing TCP failed", "tls", "true")
	}

	return conn, ProbeSuccess()
}

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

func ProbeTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) ProbeResult {
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
	deadline, _ := ctx.Deadline()

	conn, dialResult := dialTCP(ctx, target, module, registry, logger)
	if !dialResult.success {
		return dialResult
	}
	defer conn.Close()
	logger.Info("Successfully dialed")

	// Set a deadline to prevent the following code from blocking forever.
	// If a deadline cannot be set, better fail the probe by returning an error
	// now rather than blocking forever.
	if err := conn.SetDeadline(deadline); err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error setting deadline")
	}
	if module.TCP.TLS {
		state := conn.(*tls.Conn).ConnectionState()
		registry.MustRegister(probeSSLEarliestCertExpiry, probeTLSVersion, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
		probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).Unix()))
		probeTLSVersion.WithLabelValues(getTLSVersion(&state)).Set(1)
		probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(&state).Unix()))
		probeSSLLastInformation.WithLabelValues(getFingerprint(&state), getSubject(&state), getIssuer(&state), getDNSNames(&state), getSerialNumber(&state)).Set(1)
	}
	scanner := bufio.NewScanner(conn)
	for i, qr := range module.TCP.QueryResponse {
		logger.Info("Processing query response entry", "entry_number", i)
		send := qr.Send
		if qr.Expect.Regexp != nil {
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				logger.Debug("Read line", "line", scanner.Text())
				match = qr.Expect.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					logger.Info("Regexp matched", "regexp", qr.Expect.Regexp, "line", scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				logger.Error("Scanner Error", "error", scanner.Err())
				return ProbeFailure("Error reading from connection")
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				logger.Error("Regexp did not match", "regexp", qr.Expect.Regexp.String(), "line", scanner.Text())
				return ProbeFailure("Regexp did not match")
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
				logger.Error(err.Error())
				return ProbeFailure("Failed to send")
			}
		}
		if qr.StartTLS {
			// Upgrade TCP connection to TLS.
			tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
			if err != nil {
				logger.Error(err.Error())
				return ProbeFailure("Failed to create TLS configuration")
			}
			if tlsConfig.ServerName == "" {
				// Use target-hostname as default for TLS-servername.
				targetAddress, _, _ := net.SplitHostPort(target) // Had succeeded in dialTCP already.
				tlsConfig.ServerName = targetAddress
			}
			tlsConn := tls.Client(conn, tlsConfig)
			defer tlsConn.Close()

			// Initiate TLS handshake (required here to get TLS state).
			if err := tlsConn.Handshake(); err != nil {
				logger.Error(err.Error())
				return ProbeFailure("TLS Handshake (client) failed")
			}
			logger.Info("TLS Handshake (client) succeeded.")
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
	return ProbeSuccess()
}
