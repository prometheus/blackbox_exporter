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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/tidwall/gjson"
)

// Takes a list of regexs `exps` and checks them against the body. Return based on `shouldMatch`
func checkExps(body []byte, exps []string, shouldMatch bool, logger log.Logger) bool {
	for _, expression := range exps {
		re, err := regexp.Compile(expression)
		if err != nil {
			level.Error(logger).Log("msg", "Could not compile regular expression", "regexp", expression, "err", err)
			return false
		}
		if !shouldMatch && re.Match(body) {
			level.Error(logger).Log("msg", "Body matched regular expression", "regexp", expression)
			return false
		}
		if shouldMatch && !re.Match(body) {
			level.Error(logger).Log("msg", "Body didn't match regular expression", "regexp", expression)
			return false
		}

	}
	return true
}

func matchRegularExpressions(reader io.Reader, httpConfig config.HTTPProbe, logger log.Logger) bool {
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		level.Error(logger).Log("msg", "Error reading HTTP body", "err", err)
		return false
	}
	matchesPassed := checkExps(body, httpConfig.FailIfMatchesRegexp, false, logger)
	notMatchesPassed := checkExps(body, httpConfig.FailIfNotMatchesRegexp, true, logger)

	return matchesPassed && notMatchesPassed

}

func matchJsonExpressions(reader io.Reader, httpConfig config.HTTPProbe, logger log.Logger) bool {
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		level.Error(logger).Log("msg", "Error reading HTTP body", "err", err)
		return false
	}
	level.Debug(logger).Log("body", body)
	for _, jsonp := range httpConfig.JsonMatches {
		jsonMatch := gjson.GetBytes(body, jsonp.JsonPath)
		level.Debug(logger).Log("json_path", jsonp.JsonPath)

		matchesPassed := checkExps([]byte(jsonMatch.String()), jsonp.FailIfMatchesRegexp, false, logger)
		notMatchesPassed := checkExps([]byte(jsonMatch.String()), jsonp.FailIfNotMatchesRegexp, true, logger)

		if !matchesPassed || !notMatchesPassed {
			return false
		}
	}
	return true
}

func ProbeHTTP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var redirects int
	var (
		contentLengthGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "content_length",
			Help: "Length of http content response",
		})

		redirectsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_redirects",
			Help: "The number of redirects",
		})

		isSSLGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_ssl",
			Help: "Indicates if SSL was used for the final redirect",
		})

		statusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_status_code",
			Help: "Response HTTP status code",
		})

		probeSSLEarliestCertExpiryGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_ssl_earliest_cert_expiry",
			Help: "Returns earliest SSL cert expiry in unixtime",
		})

		probeHTTPVersionGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_version",
			Help: "Returns the version of HTTP of the probe response",
		})

		probeFailedDueToRegex = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_regex",
			Help: "Indicates if probe failed due to regex",
		})

		probeFailedDueToJsonRegex = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_json_regex",
			Help: "Indicates if probe failed due to json value not matching a regex",
		})
	)

	registry.MustRegister(contentLengthGauge)
	registry.MustRegister(redirectsGauge)
	registry.MustRegister(isSSLGauge)
	registry.MustRegister(statusCodeGauge)
	registry.MustRegister(probeHTTPVersionGauge)
	registry.MustRegister(probeFailedDueToRegex)
	registry.MustRegister(probeFailedDueToJsonRegex)

	httpConfig := module.HTTP

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse target URL", "err", err)
		return false
	}
	targetHost, targetPort, err := net.SplitHostPort(targetURL.Host)
	// If split fails, assuming it's a hostname without port part.
	if err != nil {
		targetHost = targetURL.Host
	}

	ip, err := chooseProtocol(module.HTTP.PreferredIPProtocol, targetHost, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}

	httpClientConfig := module.HTTP.HTTPClientConfig
	if len(httpClientConfig.TLSConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// the hostname of the target.
		httpClientConfig.TLSConfig.ServerName = targetHost
	}
	client, err := pconfig.NewHTTPClientFromConfig(&httpClientConfig)
	if err != nil {
		level.Error(logger).Log("msg", "Error generating HTTP client", "err", err)
		return false
	}

	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		level.Info(logger).Log("msg", "Received redirect", "url", r.URL.String())
		redirects = len(via)
		if redirects > 10 || httpConfig.NoFollowRedirects {
			level.Info(logger).Log("msg", "Not following redirect")
			return errors.New("Don't follow redirects")
		}
		return nil
	}

	if httpConfig.Method == "" {
		httpConfig.Method = "GET"
	}

	// Replace the host field in the URL with the IP we resolved.
	origHost := targetURL.Host
	if targetPort == "" {
		targetURL.Host = "[" + ip.String() + "]"
	} else {
		targetURL.Host = net.JoinHostPort(ip.String(), targetPort)
	}
	request, err := http.NewRequest(httpConfig.Method, targetURL.String(), nil)
	request.Host = origHost
	request = request.WithContext(ctx)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating request", "err", err)
		return
	}

	for key, value := range httpConfig.Headers {
		if strings.Title(key) == "Host" {
			request.Host = value
			continue
		}
		request.Header.Set(key, value)
	}

	// If a body is configured, add it to the request.
	if httpConfig.Body != "" {
		request.Body = ioutil.NopCloser(strings.NewReader(httpConfig.Body))
	}
	level.Info(logger).Log("msg", "Making HTTP request", "url", request.URL.String(), "host", request.Host)
	resp, err := client.Do(request)
	// Err won't be nil if redirects were turned off. See https://github.com/golang/go/issues/3795
	if err != nil && resp == nil {
		level.Error(logger).Log("msg", "Error for HTTP request", "err", err)
	} else {
		defer resp.Body.Close()
		level.Info(logger).Log("msg", "Received HTTP response", "status_code", resp.StatusCode)
		if len(httpConfig.ValidStatusCodes) != 0 {
			for _, code := range httpConfig.ValidStatusCodes {
				if resp.StatusCode == code {
					success = true
					break
				}
			}
			if !success {
				level.Info(logger).Log("msg", "Invalid HTTP response status code", "status_code", resp.StatusCode,
					"valid_status_codes", fmt.Sprintf("%v", httpConfig.ValidStatusCodes))
			}
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		} else {
			level.Info(logger).Log("msg", "Invalid HTTP response status code, wanted 2xx", "status_code", resp.StatusCode)
		}

		if success && (len(httpConfig.FailIfMatchesRegexp) > 0 || len(httpConfig.FailIfNotMatchesRegexp) > 0) {
			success = matchRegularExpressions(resp.Body, httpConfig, logger)
			if success {
				probeFailedDueToRegex.Set(0)
			} else {
				probeFailedDueToRegex.Set(1)
			}
		}

		if success && len(httpConfig.JsonMatches) > 0 {
			success = matchJsonExpressions(resp.Body, httpConfig, logger)
			if success {
				probeFailedDueToJsonRegex.Set(0)
			} else {
				probeFailedDueToJsonRegex.Set(1)
			}
		}

		var httpVersionNumber float64
		httpVersionNumber, err = strconv.ParseFloat(strings.TrimPrefix(resp.Proto, "HTTP/"), 64)
		if err != nil {
			level.Error(logger).Log("msg", "Error parsing version number from HTTP version", "err", err)
		}
		probeHTTPVersionGauge.Set(httpVersionNumber)

		if len(httpConfig.ValidHTTPVersions) != 0 {
			found := false
			for _, version := range httpConfig.ValidHTTPVersions {
				if version == resp.Proto {
					found = true
					break
				}
			}
			if !found {
				level.Error(logger).Log("msg", "Invalid HTTP version number", "version", httpVersionNumber)
				success = false
			}
		}

	}

	if resp == nil {
		resp = &http.Response{}
	}

	if resp.TLS != nil {
		isSSLGauge.Set(float64(1))
		registry.MustRegister(probeSSLEarliestCertExpiryGauge)
		probeSSLEarliestCertExpiryGauge.Set(float64(getEarliestCertExpiry(resp.TLS).UnixNano() / 1e9))
		if httpConfig.FailIfSSL {
			level.Error(logger).Log("msg", "Final request was over SSL")
			success = false
		}
	} else if httpConfig.FailIfNotSSL {
		level.Error(logger).Log("msg", "Final request was not over SSL")
		success = false
	}

	statusCodeGauge.Set(float64(resp.StatusCode))
	contentLengthGauge.Set(float64(resp.ContentLength))
	redirectsGauge.Set(float64(redirects))
	return
}
