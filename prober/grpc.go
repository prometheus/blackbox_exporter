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

func ProbeGRPC(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (result ProbeResult) {

	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_grpc_duration_seconds",
			Help: "Duration of gRPC request by phase",
		}, []string{"phase"})

		isSSLGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_grpc_ssl",
			Help: "Indicates if SSL was used for the connection",
		})

		statusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_grpc_status_code",
			Help: "Response gRPC status code",
		})

		healthCheckResponseGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_grpc_healthcheck_response",
			Help: "Response HealthCheck response",
		}, []string{"serving_status"})

		probeSSLEarliestCertExpiryGauge = prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)

		probeTLSVersion = prometheus.NewGaugeVec(
			probeTLSInfoGaugeOpts,
			[]string{"version"},
		)

		probeSSLLastInformation = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probe_ssl_last_chain_info",
				Help: "Contains SSL leaf certificate information",
			},
			[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber"},
		)
	)

	for _, lv := range []string{"resolve"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(isSSLGauge)
	registry.MustRegister(statusCodeGauge)
	registry.MustRegister(healthCheckResponseGaugeVec)

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Could not parse target URL")
	}

	targetHost, targetPort, err := net.SplitHostPort(targetURL.Host)
	// If split fails, assuming it's a hostname without port part.
	if err != nil {
		targetHost = targetURL.Host
	}

	tlsConfig, err := pconfig.NewTLSConfig(&module.GRPC.TLSConfig)
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error creating TLS configuration")
	}

	ip, lookupTime, err := chooseProtocol(ctx, module.GRPC.PreferredIPProtocol, module.GRPC.IPProtocolFallback, targetHost, registry, logger)
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error resolving address")
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)
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
	durationGaugeVec.WithLabelValues("check").Add(time.Since(checkStart).Seconds())

	for servingStatusName := range grpc_health_v1.HealthCheckResponse_ServingStatus_value {
		healthCheckResponseGaugeVec.WithLabelValues(servingStatusName).Set(float64(0))
	}
	if servingStatus != "" {
		healthCheckResponseGaugeVec.WithLabelValues(servingStatus).Set(float64(1))
	}

	if serverPeer != nil {
		tlsInfo, tlsOk := serverPeer.AuthInfo.(credentials.TLSInfo)
		if tlsOk {
			registry.MustRegister(probeSSLEarliestCertExpiryGauge, probeTLSVersion, probeSSLLastInformation)
			isSSLGauge.Set(float64(1))
			probeSSLEarliestCertExpiryGauge.Set(float64(getEarliestCertExpiry(&tlsInfo.State).Unix()))
			probeTLSVersion.WithLabelValues(getTLSVersion(&tlsInfo.State)).Set(1)
			probeSSLLastInformation.WithLabelValues(getFingerprint(&tlsInfo.State), getSubject(&tlsInfo.State), getIssuer(&tlsInfo.State), getDNSNames(&tlsInfo.State), getSerialNumber(&tlsInfo.State)).Set(1)
		} else {
			isSSLGauge.Set(float64(0))
		}
	}
	statusCodeGauge.Set(float64(statusCode))

	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Can't connect to the grpc server")
	} else if !ok {
		return ProbeFailure("Can't connect to the grpc server")
	} else {
		logger.Debug("connect the grpc server successfully")
		result = ProbeSuccess()
	}

	return
}
