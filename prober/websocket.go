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
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
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

	registry.MustRegister(isConnected)
	registry.MustRegister(httpStatusCode)

	dialer := websocket.Dialer{
		TLSClientConfig: module.Websocket.WSHTTPClientConfig.TLSConfig,
	}

	connection, resp, err := dialer.DialContext(ctx, targetURL.String(), constructHeadersFromConfig(&module.Websocket.WSHTTPClientConfig, logger))
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
		probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_websocket_failed_due_to_regex",
			Help: "Indicates if probe failed due to regex",
		})
		registry.MustRegister(probeFailedDueToRegex)

		queryMatched := true
		for _, qr := range module.Websocket.QueryResponse {
			var message []byte
			var err error

			if qr.Expect.Regexp != nil {
				_, message, err = connection.ReadMessage()
				if err != nil {
					logger.Error("Error reading message", "err", err)
					queryMatched = false
					break
				}
			}

			send, matched := processWebsocketQueryRegexp(&qr, message, logger)
			if !matched {
				queryMatched = false
				break
			}

			if send != "" {
				err = connection.WriteMessage(websocket.TextMessage, []byte(send))
				if err != nil {
					logger.Error("Error sending message", "err", err)
					queryMatched = false
					break
				}
				logger.Debug("message sent", "message", send)
			}
		}
		if queryMatched {
			probeFailedDueToRegex.Set(0)
		} else {
			probeFailedDueToRegex.Set(1)
		}
	}

	return true
}

func processWebsocketQueryRegexp(qr *config.QueryResponse, message []byte, logger *slog.Logger) (string, bool) {
	send := qr.Send

	if qr.Expect.Regexp != nil {
		match := qr.Expect.Regexp.FindSubmatchIndex(message)
		if match == nil {
			logger.Error("Regexp did not match", "regexp", qr.Expect.Regexp, "line", message)
			return "", false
		}

		logger.Debug("regexp matched", "regexp", qr.Expect.Regexp, "line", message)
		send = string(qr.Expect.Regexp.Expand(nil, []byte(send), message, match))
	}

	return send, true
}

func constructHeadersFromConfig(config *config.WSHTTPClientConfig, logger *slog.Logger) map[string][]string {
	headers := http.Header{}
	if config.BasicAuth.Username != "" || config.BasicAuth.Password != "" {
		headers.Add("Authorization", config.BasicAuth.BasicAuthHeader())
	} else if config.BearerToken != "" {
		headers.Add("Authorization", "Bearer "+config.BearerToken)
	}
	for key, value := range config.HTTPHeaders {
		if _, ok := value.(string); ok {
			headers.Add(key, value.(string))
		} else if _, ok := value.([]string); ok {
			headers[cases.Title(language.English).String(key)] = append(headers[key], value.([]string)...)
		}
	}

	logger.Debug("Constructed headers", "headers", headers)
	return headers
}
