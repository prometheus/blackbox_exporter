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
	"net/url"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"golang.org/x/net/proxy"

	"github.com/prometheus/blackbox_exporter/config"
)

func dialTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (net.Conn, error) {
	var dialProtocol, dialTarget string
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		logger.Error("Error splitting target address and port", "err", err)
		return nil, err
	}

	proxyURL := module.TCP.ProxyConfig.ProxyURL.URL
	if proxyURL != nil {
		// When a proxy is configured, skip local DNS resolution and let the
		// proxy resolve the target hostname.
		dialProtocol = "tcp"
		dialTarget = net.JoinHostPort(targetAddress, port)
	} else {
		ip, _, err := chooseProtocol(ctx, module.TCP.IPProtocol, module.TCP.IPProtocolFallback, targetAddress, registry, logger)
		if err != nil {
			logger.Error("Error resolving address", "err", err)
			return nil, err
		}

		if ip.IP.To4() == nil {
			dialProtocol = "tcp6"
		} else {
			dialProtocol = "tcp4"
		}

		dialTarget = net.JoinHostPort(ip.String(), port)
	}

	if len(module.TCP.SourceIPAddress) > 0 {
		srcIP := net.ParseIP(module.TCP.SourceIPAddress)
		if srcIP == nil {
			logger.Error("Error parsing source ip address", "srcIP", module.TCP.SourceIPAddress)
			return nil, fmt.Errorf("error parsing source ip address: %s", module.TCP.SourceIPAddress)
		}
		logger.Debug("Using local address", "srcIP", srcIP)
		dialer.LocalAddr = &net.TCPAddr{IP: srcIP}
	}

	if proxyURL != nil {
		if module.TCP.ProxyUsername != "" {
			proxyURLCopy := *proxyURL
			proxyURLCopy.User = url.UserPassword(module.TCP.ProxyUsername, string(module.TCP.ProxyPassword))
			proxyURL = &proxyURLCopy
		}
		proxyDialer, err := proxy.FromURL(proxyURL, dialer)
		if err != nil {
			logger.Error("Error creating proxy dialer", "err", err)
			return nil, err
		}
		contextDialer, ok := proxyDialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("proxy dialer does not support context")
		}
		if !module.TCP.TLS {
			logger.Debug("Dialing TCP through proxy without TLS", "proxy", proxyURL)
			return contextDialer.DialContext(ctx, dialProtocol, dialTarget)
		}
		tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
		if err != nil {
			logger.Error("Error creating TLS configuration", "err", err)
			return nil, err
		}
		if len(tlsConfig.ServerName) == 0 {
			tlsConfig.ServerName = targetAddress
		}
		logger.Debug("Dialing TCP through proxy with TLS", "proxy", proxyURL)
		conn, err := contextDialer.DialContext(ctx, dialProtocol, dialTarget)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	if !module.TCP.TLS {
		logger.Debug("Dialing TCP without TLS")
		return dialer.DialContext(ctx, dialProtocol, dialTarget)
	}
	tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
	if err != nil {
		logger.Error("Error creating TLS configuration", "err", err)
		return nil, err
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

	logger.Debug("Dialing TCP with TLS")
	return tls.DialWithDialer(dialer, dialProtocol, dialTarget, tlsConfig)
}

func ProbeTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) bool {
	conn, err := dialTCP(ctx, target, module, registry, logger)
	if err != nil {
		logger.Error("Error dialing TCP", "err", err)
		return false
	}
	defer conn.Close()
	logger.Debug("Successfully dialed")

	return probeQueryResponses(ctx, target, conn, module, "tcp", registry, logger)
}
