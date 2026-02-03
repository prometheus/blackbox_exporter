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
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	promconfig "github.com/prometheus/common/config"
)

func ProbeWebsocket(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (success bool) {

	targetURL, err := url.Parse(target)
	if err != nil {
		logger.Error("Could not parse target URL", "err", err)
		return false
	}

	logger.Debug("probing websocket", "target", targetURL.String())

	httpStatusCode := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_websocket_status_code",
		Help: "Response HTTP status code",
	})
	isConnected := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_websocket_connection_upgraded",
		Help: "Indicates if the websocket connection was successfully upgraded",
	})
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_websocket_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})

	registry.MustRegister(isConnected)
	registry.MustRegister(httpStatusCode)
	registry.MustRegister(probeFailedDueToRegex)

	tlsConfig, err := promconfig.NewTLSConfig(&module.Websocket.HTTPClientConfig.TLSConfig)
	if err != nil {
		logger.Error("Error creating TLS config", "err", err)
		return false
	}

	ip, _, err := chooseProtocol(ctx, module.Websocket.IPProtocol, module.Websocket.IPProtocolFallback, targetURL.Hostname(), registry, logger)
	if err != nil {
		logger.Error("Error resolving address", "err", err)
		return false
	}

	if len(tlsConfig.ServerName) == 0 {
		// as we've resolved the address and passed the ip to the dialer,
		// we need to set the server name manually
		tlsConfig.ServerName = targetURL.Hostname()
	}

	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// use chosen protocol to dial but use ip as we've resolved the address
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		},
	}

	connection, resp, err := dialer.DialContext(ctx, targetURL.String(), constructHeadersFromConfig(module.Websocket, logger))
	if resp != nil {
		httpStatusCode.Set(float64(resp.StatusCode))
	}
	if err != nil {
		logger.Error("Error dialing websocket", "err", err)
		return false
	}
	defer connection.Close()

	isConnected.Set(1)

	if len(module.Websocket.QueryResponse) > 0 {

		for _, qr := range module.Websocket.QueryResponse {
			if !matchQueryResponse(qr, connection, logger) {
				probeFailedDueToRegex.Set(1)
				return true
			}
		}
		probeFailedDueToRegex.Set(0)
	}

	return true
}

func matchQueryResponse(qr config.QueryResponse, conn *websocket.Conn, logger *slog.Logger) bool {
	var message []byte
	var err error

	if qr.Expect.Regexp != nil {
		_, message, err = conn.ReadMessage()
		if err != nil {
			logger.Error("Error reading message", "err", err)
			return false
		}
	}

	send, matched := processWebsocketQueryRegexp(&qr, message, logger)
	if !matched {
		return false
	}

	if send != "" {
		err = conn.WriteMessage(websocket.TextMessage, []byte(send))
		if err != nil {
			logger.Error("Error sending message", "err", err)
			return false
		}
		logger.Debug("message sent", "message", send)
	}
	return true
}

func processWebsocketQueryRegexp(qr *config.QueryResponse, message []byte, logger *slog.Logger) (string, bool) {
	send := qr.Send

	if qr.Expect.Regexp != nil {
		match := qr.Expect.FindSubmatchIndex(message)
		if match == nil {
			logger.Error("Regexp did not match", "regexp", qr.Expect.Regexp, "line", message)
			return "", false
		}

		logger.Debug("regexp matched", "regexp", qr.Expect.Regexp, "line", message)
		send = string(qr.Expect.Expand(nil, []byte(send), message, match))
	}

	return send, true
}

func constructHeadersFromConfig(websocketConfig config.WebsocketProbe, logger *slog.Logger) map[string][]string {
	headers := http.Header{}
	config := websocketConfig.HTTPClientConfig

	if config.BasicAuth != nil {
		username := config.BasicAuth.Username
		if config.BasicAuth.UsernameFile != "" {
			b, err := os.ReadFile(config.BasicAuth.UsernameFile)
			if err != nil {
				logger.Error("Unable to read basic auth username file", "file", config.BasicAuth.UsernameFile, "err", err)
			} else {
				username = strings.TrimSpace(string(b))
			}
		}

		password := config.BasicAuth.Password
		if config.BasicAuth.PasswordFile != "" {
			b, err := os.ReadFile(config.BasicAuth.PasswordFile)
			if err != nil {
				logger.Error("Unable to read basic auth password file", "file", config.BasicAuth.PasswordFile, "err", err)
			} else {
				password = promconfig.Secret(strings.TrimSpace(string(b)))
			}
		}
		headers.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+string(password))))
	}

	if config.Authorization != nil {
		credentials := config.Authorization.Credentials
		if config.Authorization.CredentialsFile != "" {
			b, err := os.ReadFile(config.Authorization.CredentialsFile)
			if err != nil {
				logger.Error("Unable to read authorization credentials file", "file", config.Authorization.CredentialsFile, "err", err)
			} else {
				credentials = promconfig.Secret(strings.TrimSpace(string(b)))
			}
		}
		if len(credentials) > 0 {
			authType := config.Authorization.Type
			if authType == "" {
				authType = "Bearer"
			}
			headers.Add("Authorization", authType+" "+string(credentials))
		}
	}

	// Custom headers
	for headerName, header := range websocketConfig.Headers.Headers {
		for _, value := range header.Values {
			headers.Add(headerName, value)
		}
		for _, secret := range header.Secrets {
			headers.Add(headerName, string(secret))
		}
		for _, file := range header.Files {
			b, err := os.ReadFile(file)
			if err != nil {
				logger.Error("Unable to read header file", "file", file, "err", err)
				continue
			}
			headers.Add(headerName, strings.TrimSpace(string(b)))
		}
	}

	logger.Debug("Constructed headers", "headers", headers)
	return headers
}
