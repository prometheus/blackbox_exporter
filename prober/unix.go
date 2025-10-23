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
	"crypto/tls"
	"log/slog"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

func dialUnix(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (net.Conn, error) {
	dialer := &net.Dialer{}

	if !module.Unix.TLS {
		logger.Debug("Dialing unix without TLS")
		return dialer.DialContext(ctx, "unix", target)
	}

	tlsConfig, err := pconfig.NewTLSConfig(&module.Unix.TLSConfig)
	if err != nil {
		logger.Error("Error creating TLS configuration", "err", err)
		return nil, err
	}

	timeoutDeadline, _ := ctx.Deadline()
	dialer.Deadline = timeoutDeadline

	logger.Debug("Dialing unix with TLS")
	return tls.DialWithDialer(dialer, "unix", target, tlsConfig)
}

func ProbeUnix(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) bool {
	conn, err := dialUnix(ctx, target, module, registry, logger)
	if err != nil {
		logger.Error("Error dialing unix", "err", err)
		return false
	}
	defer conn.Close()
	logger.Debug("Successfully dialed")

	return probeQueryResponses(ctx, target, conn, module, "unix", registry, logger)
}
