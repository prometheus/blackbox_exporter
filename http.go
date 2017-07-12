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

package main

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/log"
)

func matchRegularExpressions(reader io.Reader, httpConfig HTTPProbe) bool {
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Errorf("Error reading HTTP body: %s", err)
		return false
	}
	for _, expression := range httpConfig.FailIfMatchesRegexp {
		re, err := regexp.Compile(expression)
		if err != nil {
			log.Errorf("Could not compile expression %q as regular expression: %s", expression, err)
			return false
		}
		if re.Match(body) {
			return false
		}
	}
	for _, expression := range httpConfig.FailIfNotMatchesRegexp {
		re, err := regexp.Compile(expression)
		if err != nil {
			log.Errorf("Could not compile expression %q as regular expression: %s", expression, err)
			return false
		}
		if !re.Match(body) {
			return false
		}
	}
	return true
}

func probeHTTP(ctx context.Context, target string, module Module, registry *prometheus.Registry) (success bool) {
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
	)

	registry.MustRegister(contentLengthGauge)
	registry.MustRegister(redirectsGauge)
	registry.MustRegister(isSSLGauge)
	registry.MustRegister(statusCodeGauge)
	registry.MustRegister(probeHTTPVersionGauge)

	httpConfig := module.HTTP

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return false
	}
	targetHost, targetPort, err := net.SplitHostPort(targetURL.Host)
	// If split fails, assuming it's a hostname without port part.
	if err != nil {
		targetHost = targetURL.Host
	}

	ip, err := chooseProtocol(module.HTTP.PreferredIPProtocol, targetHost, registry)
	if err != nil {
		return false
	}

	httpClientConfig := &module.HTTP.HTTPClientConfig

	client, err := config.NewHTTPClientFromConfig(httpClientConfig)
	if err != nil {
		log.Errorf("Error generating HTTP client: %v", err)
		return false
	}

	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		redirects = len(via)
		if redirects > 10 || httpConfig.NoFollowRedirects {
			return errors.New("Don't follow redirects")
		}
		return nil
	}

	if httpConfig.Method == "" {
		httpConfig.Method = "GET"
	}

	request, err := http.NewRequest(httpConfig.Method, target, nil)
	request.Host = targetURL.Host
	request = request.WithContext(ctx)
	if targetPort == "" {
		targetURL.Host = ip.String()
	} else {
		targetURL.Host = net.JoinHostPort(ip.String(), targetPort)
	}

	if err != nil {
		log.Errorf("Error creating request for target %s: %s", target, err)
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
	resp, err := client.Do(request)
	// Err won't be nil if redirects were turned off. See https://github.com/golang/go/issues/3795
	if err != nil && resp == nil {
		log.Errorf("Error for HTTP request to %s: %s", target, err)
		success = false
	} else {
		defer resp.Body.Close()
		if len(httpConfig.ValidStatusCodes) != 0 {
			for _, code := range httpConfig.ValidStatusCodes {
				if resp.StatusCode == code {
					success = true
					break
				}
			}
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		}

		if success && (len(httpConfig.FailIfMatchesRegexp) > 0 || len(httpConfig.FailIfNotMatchesRegexp) > 0) {
			success = matchRegularExpressions(resp.Body, httpConfig)
		}

		var httpVersionNumber float64
		httpVersionNumber, err = strconv.ParseFloat(strings.TrimPrefix(resp.Proto, "HTTP/"), 64)
		if err != nil {
			log.Errorf("Error parsing version number from HTTP version: %v", err)
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
			success = false
		}
	} else if httpConfig.FailIfNotSSL {
		success = false
	}

	statusCodeGauge.Set(float64(resp.StatusCode))
	contentLengthGauge.Set(float64(resp.ContentLength))
	redirectsGauge.Set(float64(redirects))
	return
}
