package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/log"
)

func matchRegularExpressions(body []byte, config HTTPProbe) bool {
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

func getEarliestCertExpiry(state *tls.ConnectionState) time.Time {
	earliest := time.Time{}
	for _, cert := range state.PeerCertificates {
		if (earliest.IsZero() || cert.NotAfter.Before(earliest)) && !cert.NotAfter.IsZero() {
			earliest = cert.NotAfter
		}
	}
	return earliest
}

func probeHTTP(target string, w http.ResponseWriter, module Module) (success bool) {
	var isSSL, redirects int
	var actualContentLength = -1
	config := module.HTTP

	client := &http.Client{
		Timeout: module.Timeout,
	}

	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		redirects = len(via)
		if config.NoFollowRedirects {
			return errors.New("Don't follow redirects")
		} else if redirects > 10 {
			return errors.New("Maximum redirects exceeded")
		} else {
			return nil
		}
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	if config.Method == "" {
		config.Method = "GET"
	}
	if config.Path == "" {
		config.Path = "/"
	}

	log.Infof("probeHTTP to %s%s", target, config.Path)

	request, err := http.NewRequest(config.Method, target + config.Path, nil)
	if err != nil {
		log.Errorf("Error creating request for target %s: %s", target, err)
		return
	}

	resp, err := client.Do(request)
	// Err won't be nil if redirects were turned off. See https://github.com/golang/go/issues/3795
	if err != nil && resp == nil {
		log.Warnf("Error for HTTP request to %s: %s", target, err)
	} else {
		defer resp.Body.Close()

		var statusCodeOkay = false
		var regexMatchOkay = true
		var tlsOkay = true

		// First, check the status code of the response.

		if len(config.ValidStatusCodes) != 0 {
			for _, code := range config.ValidStatusCodes {
				if resp.StatusCode == code {
					statusCodeOkay = true
					break
				}
			}
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			statusCodeOkay = true
		}

		// Next, process the body of the response for size and content.

		if statusCodeOkay {
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				actualContentLength = len(body)
				if len(config.FailIfMatchesRegexp) > 0 || len(config.FailIfNotMatchesRegexp) > 0 {
					regexMatchOkay = matchRegularExpressions(body, config)
				}
			} else {
				log.Errorf("Error reading HTTP body: %s", err)
			}
		}

		// Finally check TLS

		if resp.TLS != nil {
			isSSL = 1
			fmt.Fprintf(w, "probe_ssl_earliest_cert_expiry %f\n",
				float64(getEarliestCertExpiry(resp.TLS).UnixNano())/1e9)
			if config.FailIfSSL {
				tlsOkay = false
			}
		} else if config.FailIfNotSSL {
			tlsOkay = false
		}

		success = statusCodeOkay && regexMatchOkay && tlsOkay
	}
	fmt.Fprintf(w, "probe_http_status_code %d\n", resp.StatusCode)
	fmt.Fprintf(w, "probe_http_content_length %d\n", resp.ContentLength)
	fmt.Fprintf(w, "probe_http_actual_content_length %d\n", actualContentLength)
	fmt.Fprintf(w, "probe_http_redirects %d\n", redirects)
	fmt.Fprintf(w, "probe_http_ssl %d\n", isSSL)
	return
}
