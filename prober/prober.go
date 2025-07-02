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
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/blackbox_exporter/config"
)

type ProbeFn func(ctx context.Context, target string, config config.Module, registry *prometheus.Registry, logger *slog.Logger) bool

const (
	helpSSLEarliestCertExpiry     = "Returns the earliest expiry of any peer certificate returned by the server as an unix timestamp. This can include certificates that are not validated by TLS clients. In rare server configurations this might return a time in the past, even for valid TLS certificate chains."
	helpSSLChainExpiryInTimeStamp = "Returns the earliest expiry of any validated TLS certificate as an unix timestamp. This indicates the time when connections will start to fail, unless a certificate is renewed."
	helpProbeTLSInfo              = "Returns the TLS version used or NaN when unknown"
	helpProbeTLSCipher            = "Returns the TLS cipher negotiated during handshake"
)

var (
	sslEarliestCertExpiryGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: helpSSLEarliestCertExpiry,
	}

	sslChainExpiryInTimeStampGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_ssl_last_chain_expiry_timestamp_seconds",
		Help: helpSSLChainExpiryInTimeStamp,
	}

	probeTLSInfoGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_tls_version_info",
		Help: helpProbeTLSInfo,
	}

	probeTLSCipherGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_tls_cipher_info",
		Help: helpProbeTLSCipher,
	}
)
