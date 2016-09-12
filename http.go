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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/prometheus/common/log"
)

func matchResponseHeaders(responseHeaders http.Header, config HTTPProbe) bool {
	for headerName, headerConfig := range config.ResponseHeaders {
		headerValue, exists := responseHeaders[headerName]
		if !exists {
			if headerConfig.Required {
				return false
			}
			continue
		}

		headerValueBytes := []byte(headerValue[0])

		for _, expression := range headerConfig.FailIfMatchesRegexp {
			re, err := regexp.Compile(expression)
			if err != nil {
				log.Errorf("Could not compile expression %q as regular expression: %s", expression, err)
				return false
			}

			if re.Match(headerValueBytes) {
				return false
			}
		}

		for _, expression := range headerConfig.FailIfNotMatchesRegexp {
			re, err := regexp.Compile(expression)
			if err != nil {
				log.Errorf("Could not compile expression %q as regular expression: %s", expression, err)
				return false
			}
			if !re.Match(headerValueBytes) {
				return false
			}
		}
	}
	return true
}

func matchRegularExpressions(reader io.Reader, config HTTPProbe) bool {
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Errorf("Error reading HTTP body: %s", err)
		return false
	}
	for _, expression := range config.FailIfMatchesRegexp {
		re, err := regexp.Compile(expression)
		if err != nil {
			log.Errorf("Could not compile expression %q as regular expression: %s", expression, err)
			return false
		}
		if re.Match(body) {
			return false
		}
	}
	for _, expression := range config.FailIfNotMatchesRegexp {
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

func probeHTTP(target string, w http.ResponseWriter, module Module) (success bool) {
	var isSSL, redirects int
	config := module.HTTP

	client := &http.Client{
		Timeout: module.Timeout,
	}

	tlsconfig, err := module.HTTP.TLSConfig.GenerateConfig()
	if err != nil {
		log.Errorf("Error generating TLS config: %s", err)
		return false
	}
	client.Transport = &http.Transport{
		TLSClientConfig: tlsconfig,
	}

	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		redirects = len(via)
		if redirects > 10 || config.NoFollowRedirects {
			return errors.New("Don't follow redirects")
		}
		return nil
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	if config.Method == "" {
		config.Method = "GET"
	}

	request, err := http.NewRequest(config.Method, target, nil)
	if err != nil {
		log.Errorf("Error creating request for target %s: %s", target, err)
		return
	}

	for key, value := range config.Headers {
		if strings.Title(key) == "Host" {
			request.Host = value
			continue
		}
		request.Header.Set(key, value)
	}

	resp, err := client.Do(request)
	// Err won't be nil if redirects were turned off. See https://github.com/golang/go/issues/3795
	if err != nil && resp == nil {
		log.Warnf("Error for HTTP request to %s: %s", target, err)
	} else {
		defer resp.Body.Close()
		if len(config.ValidStatusCodes) != 0 {
			for _, code := range config.ValidStatusCodes {
				if resp.StatusCode == code {
					success = true
					break
				}
			}
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		}

		if success && len(config.ResponseHeaders) > 0 {
			success = matchResponseHeaders(resp.Header, config)
		}

		if success && (len(config.FailIfMatchesRegexp) > 0 || len(config.FailIfNotMatchesRegexp) > 0) {
			success = matchRegularExpressions(resp.Body, config)
		}
	}

	if resp == nil {
		resp = &http.Response{}
	}

	if resp.TLS != nil {
		isSSL = 1
		fmt.Fprintf(w, "probe_ssl_earliest_cert_expiry %f\n",
			float64(getEarliestCertExpiry(resp.TLS).UnixNano())/1e9)
		if config.FailIfSSL {
			success = false
		}
	} else if config.FailIfNotSSL {
		success = false
	}
	fmt.Fprintf(w, "probe_http_status_code %d\n", resp.StatusCode)
	fmt.Fprintf(w, "probe_http_content_length %d\n", resp.ContentLength)
	fmt.Fprintf(w, "probe_http_redirects %d\n", redirects)
	fmt.Fprintf(w, "probe_http_ssl %d\n", isSSL)
	return
}
