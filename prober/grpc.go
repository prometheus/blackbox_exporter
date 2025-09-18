// Copyright 2021 The Prometheus Authors
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
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/blackbox_exporter/config"
	metrics "github.com/prometheus/blackbox_exporter/internal/metrics/grpc"
	"github.com/prometheus/blackbox_exporter/internal/metrics/other"
	"github.com/prometheus/blackbox_exporter/internal/metrics/ssl"
	"github.com/prometheus/blackbox_exporter/internal/metrics/tls"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type GRPCHealthCheck interface {
	Check(c context.Context, service string) (bool, codes.Code, *peer.Peer, string, error)
}

type gRPCHealthCheckClient struct {
	client grpc_health_v1.HealthClient
	conn   *grpc.ClientConn
}

func NewGrpcHealthCheckClient(conn *grpc.ClientConn) GRPCHealthCheck {
	client := new(gRPCHealthCheckClient)
	client.client = grpc_health_v1.NewHealthClient(conn)
	client.conn = conn
	return client
}

func (c *gRPCHealthCheckClient) Close() error {
	return c.conn.Close()
}

func (c *gRPCHealthCheckClient) Check(ctx context.Context, service string) (bool, codes.Code, *peer.Peer, string, error) {
	var res *grpc_health_v1.HealthCheckResponse
	var err error
	req := grpc_health_v1.HealthCheckRequest{
		Service: service,
	}

	serverPeer := new(peer.Peer)
	res, err = c.client.Check(ctx, &req, grpc.Peer(serverPeer))
	if err == nil {
		if res.GetStatus() == grpc_health_v1.HealthCheckResponse_SERVING {
			return true, codes.OK, serverPeer, res.Status.String(), nil
		}
		return false, codes.OK, serverPeer, res.Status.String(), nil
	}

	returnStatus, _ := status.FromError(err)

	return false, returnStatus.Code(), nil, "", err
}

func ProbeGRPC(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (success bool) {
	var (
		durationGaugeVec                = metrics.NewProbeDurationSeconds()
		isSSLGauge                      = metrics.NewProbeSsl()
		statusCodeGauge                 = metrics.NewProbeStatusCode()
		healthCheckResponseGaugeVec     = metrics.NewProbeHealthcheckResponse()
		probeSSLEarliestCertExpiryGauge = ssl.NewProbeEarliestCertExpiry()
		probeTLSVersion                 = tls.NewProbeVersion()
		probeSSLLastInformation         = ssl.NewProbeLastChainInfo()
	)
	durationGaugeVec.With(other.PhaseResolve)

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(isSSLGauge)
	registry.MustRegister(statusCodeGauge)
	registry.MustRegister(healthCheckResponseGaugeVec)

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		logger.Error("Could not parse target URL", "err", err)
		return false
	}

	targetHost, targetPort, err := net.SplitHostPort(targetURL.Host)
	// If split fails, assuming it's a hostname without port part.
	if err != nil {
		targetHost = targetURL.Host
	}

	tlsConfig, err := pconfig.NewTLSConfig(&module.GRPC.TLSConfig)
	if err != nil {
		logger.Error("Error creating TLS configuration", "err", err)
		return false
	}

	ip, lookupTime, err := chooseProtocol(ctx, module.GRPC.PreferredIPProtocol, module.GRPC.IPProtocolFallback, targetHost, registry, logger)
	if err != nil {
		logger.Error("Error resolving address", "err", err)
		return false
	}
	durationGaugeVec.With(other.PhaseResolve).Add(lookupTime)
	checkStart := time.Now()
	if len(tlsConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// the hostname of the target.
		tlsConfig.ServerName = targetHost
	}

	if targetPort == "" {
		targetURL.Host = "[" + ip.String() + "]"
	} else {
		targetURL.Host = net.JoinHostPort(ip.String(), targetPort)
	}

	var opts []grpc.DialOption
	target = targetHost + ":" + targetPort
	if !module.GRPC.TLS {
		logger.Debug("Dialing GRPC without TLS")
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if len(targetPort) == 0 {
			target = targetHost + ":80"
		}
	} else {
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
		if len(targetPort) == 0 {
			target = targetHost + ":443"
		}
	}

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		logger.Error("did not connect", "err", err)
	}

	client := NewGrpcHealthCheckClient(conn)
	defer conn.Close()
	ok, statusCode, serverPeer, servingStatus, err := client.Check(context.Background(), module.GRPC.Service)
	durationGaugeVec.With(other.PhaseCheck).Add(time.Since(checkStart).Seconds())

	for _, ss := range []other.AttrServingStatus{
		other.ServingStatusServing,
		other.ServingStatusNotServing,
		other.ServingStatusUnknown,
		other.ServingStatusServiceUnknown,
	} {
		healthCheckResponseGaugeVec.With(ss).Set(float64(0))
	}
	if servingStatus != "" {
		healthCheckResponseGaugeVec.With(other.AttrServingStatus(servingStatus)).Set(float64(1))
	}

	if serverPeer != nil {
		tlsInfo, tlsOk := serverPeer.AuthInfo.(credentials.TLSInfo)
		if tlsOk {
			registry.MustRegister(probeSSLEarliestCertExpiryGauge, probeTLSVersion, probeSSLLastInformation)
			isSSLGauge.Set(float64(1))
			probeSSLEarliestCertExpiryGauge.Set(float64(getEarliestCertExpiry(&tlsInfo.State).Unix()))
			probeTLSVersion.With(getTLSVersion(&tlsInfo.State)).Set(1)
			probeSSLLastInformation.With(
				getFingerprint(&tlsInfo.State),
				getIssuer(&tlsInfo.State),
				getSerialNumber(&tlsInfo.State),
				getSubject(&tlsInfo.State),
				getDNSNames(&tlsInfo.State),
			).Set(1)
		} else {
			isSSLGauge.Set(float64(0))
		}
	}
	statusCodeGauge.Set(float64(statusCode))

	if !ok || err != nil {
		logger.Error("can't connect grpc server:", "err", err)
		success = false
	} else {
		logger.Debug("connect the grpc server successfully")
		success = true
	}

	return
}
