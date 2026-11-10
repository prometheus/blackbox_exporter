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
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

func dialTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (net.Conn, *tls.ConnectionState, error) {
	var dialProtocol, dialTarget string
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		logger.Error("Error splitting target address and port", "err", err)
		return nil, nil, err
	}

	ip, _, err := chooseProtocol(ctx, module.TCP.IPProtocol, module.TCP.IPProtocolFallback, targetAddress, registry, logger)
	if err != nil {
		logger.Error("Error resolving address", "err", err)
		return nil, nil, err
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
			return nil, nil, fmt.Errorf("error parsing source ip address: %s", module.TCP.SourceIPAddress)
		}
		logger.Debug("Using local address", "srcIP", srcIP)
		dialer.LocalAddr = &net.TCPAddr{IP: srcIP}
	}

	dialTarget = net.JoinHostPort(ip.String(), port)

	if !module.TCP.TLS {
		logger.Debug("Dialing TCP without TLS")
		conn, err := dialer.DialContext(ctx, dialProtocol, dialTarget)
		return conn, nil, err
	}
	tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
	if err != nil {
		logger.Error("Error creating TLS configuration", "err", err)
		return nil, nil, err
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

	// For mTLS enforcement probes, capture the server TLS state via VerifyConnection.
	// VerifyConnection fires once the server cert is received/verified but before the
	// client sends its own cert — the only point a populated ConnectionState is available
	// on connections that will ultimately fail with a rejection alert.
	var capturedTLSState atomic.Pointer[tls.ConnectionState]
	if len(module.TCP.ValidTLSAlertCodes) > 0 {
		origVerify := tlsConfig.VerifyConnection
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			capturedTLSState.Store(&cs)
			if origVerify != nil {
				return origVerify(cs)
			}
			return nil
		}
	}

	logger.Debug("Dialing TCP with TLS")
	// Dial and handshake explicitly (rather than tls.DialWithDialer) so callers
	// can, if needed, attempt a post-handshake Read on the returned *tls.Conn:
	// see the comment on the post-handshake read in ProbeTCP for why that's
	// required to observe a TLS 1.3 server's rejection alert.
	rawConn, err := dialer.DialContext(ctx, dialProtocol, dialTarget)
	if err != nil {
		return nil, nil, err
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, capturedTLSState.Load(), err
	}
	return tlsConn, capturedTLSState.Load(), nil
}

// reportCapturedTLSState publishes certificate/TLS/CRL metrics for a TLS state
// captured before an accepted rejection alert arrived, matching what a
// genuinely successful TLS/TCP connection reports via probeQueryResponses.
func reportCapturedTLSState(ctx context.Context, state *tls.ConnectionState, checkRevoked bool, registry *prometheus.Registry, logger *slog.Logger) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return
	}

	probeSSLEarliestCertExpiry := prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)
	probeSSLLastChainExpiryTimestampSeconds := prometheus.NewGauge(sslChainExpiryInTimeStampGaugeOpts)
	probeSSLLastInformation := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_ssl_last_chain_info",
			Help: "Contains SSL leaf certificate information",
		},
		[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber"},
	)
	probeTLSVersion := prometheus.NewGaugeVec(probeTLSInfoGaugeOpts, []string{"version"})
	probeTLSCipher := prometheus.NewGaugeVec(probeTLSCipherGaugeOpts, []string{"cipher"})

	registry.MustRegister(probeSSLEarliestCertExpiry, probeTLSVersion, probeTLSCipher, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
	probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(state).Unix()))
	probeTLSVersion.WithLabelValues(getTLSVersion(state)).Set(1)
	probeTLSCipher.WithLabelValues(getTLSCipher(state)).Set(1)
	probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(state).Unix()))
	probeSSLLastInformation.WithLabelValues(getFingerprint(state), getSubject(state), getIssuer(state), getDNSNames(state), getSerialNumber(state)).Set(1)
	checkCRL(ctx, state, checkRevoked, nil, registry, logger)
}

func ProbeTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) bool {
	checkTLSAlert := module.TCP.TLS && len(module.TCP.ValidTLSAlertCodes) > 0
	var probeTLSAlertCode prometheus.Gauge
	if checkTLSAlert {
		probeTLSAlertCode = prometheus.NewGauge(probeTLSAlertCodeGaugeOpts)
		registry.MustRegister(probeTLSAlertCode)
	}

	conn, capturedState, err := dialTCP(ctx, target, module, registry, logger)
	if err != nil {
		if checkTLSAlert {
			if alertCode, ok := extractTLSAlertCode(err); ok {
				probeTLSAlertCode.Set(float64(alertCode))
				if slices.Contains(module.TCP.ValidTLSAlertCodes, uint8(alertCode)) {
					logger.Debug("TLS handshake rejected with expected alert", "alert_code", uint8(alertCode))
					reportCapturedTLSState(ctx, capturedState, module.TCP.CheckRevoked, registry, logger)
					return true
				}
				logger.Error("TLS handshake rejected with unexpected alert", "alert_code", uint8(alertCode), "valid_codes", module.TCP.ValidTLSAlertCodes)
				return false
			}
		}
		logger.Error("Error dialing TCP", "err", err)
		return false
	}
	defer conn.Close()

	if checkTLSAlert {
		// A TLS 1.3 client considers its handshake complete as soon as it sends
		// its own Finished message, without waiting for the server's reaction.
		// If the server is rejecting the connection (e.g. certificate_required,
		// bad_certificate), that alert is only delivered as the next record on
		// the wire, so it surfaces on the first Read, not on Handshake itself.
		// Attempt that Read here so the alert can still be observed; TLS 1.2
		// always resolves this synchronously during dialTCP and won't reach
		// this point with unread data.
		if tlsConn, ok := conn.(*tls.Conn); ok {
			deadline, _ := ctx.Deadline()
			if err := tlsConn.SetReadDeadline(deadline); err != nil {
				logger.Error("Error setting read deadline", "err", err)
				return false
			}
			if _, readErr := tlsConn.Read(make([]byte, 1)); readErr != nil {
				if alertCode, ok := extractTLSAlertCode(readErr); ok {
					probeTLSAlertCode.Set(float64(alertCode))
					if slices.Contains(module.TCP.ValidTLSAlertCodes, uint8(alertCode)) {
						logger.Debug("TLS handshake rejected with expected alert (observed post-handshake)", "alert_code", uint8(alertCode))
						reportCapturedTLSState(ctx, capturedState, module.TCP.CheckRevoked, registry, logger)
						return true
					}
					logger.Error("TLS handshake rejected with unexpected alert (observed post-handshake)", "alert_code", uint8(alertCode), "valid_codes", module.TCP.ValidTLSAlertCodes)
					return false
				}
				logger.Error("Error reading from TLS connection while checking for a rejection alert", "err", readErr)
				return false
			}
		}
		logger.Error("TLS connection succeeded but valid_tls_alert_codes requires rejection")
		return false
	}

	logger.Debug("Successfully dialed")
	return probeQueryResponses(ctx, target, conn, module, "tcp", registry, logger)
}
