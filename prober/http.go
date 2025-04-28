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
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/google/cel-go/cel"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/version"
	"golang.org/x/net/publicsuffix"

	"github.com/prometheus/blackbox_exporter/config"
)

func matchRegularExpressions(reader io.Reader, httpConfig config.HTTPProbe, logger *slog.Logger) ProbeResult {
	body, err := io.ReadAll(reader)
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error reading HTTP body")
	}
	for _, expression := range httpConfig.FailIfBodyMatchesRegexp {
		if expression.Match(body) {
			return ProbeFailure("Body matched regular expression", "regexp", expression.String())
		}
	}
	for _, expression := range httpConfig.FailIfBodyNotMatchesRegexp {
		if !expression.Match(body) {
			return ProbeFailure("Body did not match regular expression", "regexp", expression.String())
		}
	}
	return ProbeSuccess()
}

func matchCELExpressions(ctx context.Context, reader io.Reader, httpConfig config.HTTPProbe, logger *slog.Logger) ProbeResult {
	body, err := io.ReadAll(reader)
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error reading HTTP body")
	}

	var bodyJSON any
	if err := json.Unmarshal(body, &bodyJSON); err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error unmarshalling HTTP body to JSON")
	}

	evalPayload := map[string]interface{}{
		"body": bodyJSON,
	}

	if httpConfig.FailIfBodyJsonMatchesCEL != nil {
		result, details, err := httpConfig.FailIfBodyJsonMatchesCEL.ContextEval(ctx, evalPayload)
		if err != nil {
			logger.Error(err.Error())
			return ProbeFailure("Error evaluating CEL expression")
		}
		if result.Type() != cel.BoolType {
			logger.Info("CEL evaluation details", "details", details)
			return ProbeFailure("CEL evaluation result is not a boolean")
		}
		if result.Type() == cel.BoolType && result.Value().(bool) {
			return ProbeFailure("Body matched CEL expression", "expression", httpConfig.FailIfBodyJsonMatchesCEL.Expression)
		}
	}

	if httpConfig.FailIfBodyJsonNotMatchesCEL != nil {
		result, details, err := httpConfig.FailIfBodyJsonNotMatchesCEL.ContextEval(ctx, evalPayload)
		if err != nil {
			logger.Error(err.Error())
			return ProbeFailure("Error evaluating CEL expression")
		}
		if result.Type() != cel.BoolType {
			logger.Info("CEL evaluation details", "details", details)
			return ProbeFailure("CEL evaluation result is not a boolean")

		}
		if result.Type() == cel.BoolType && !result.Value().(bool) {
			return ProbeFailure("Body did not match CEL expression", "expression", httpConfig.FailIfBodyJsonNotMatchesCEL.Expression)
		}
	}

	return ProbeSuccess()
}

func matchRegularExpressionsOnHeaders(header http.Header, httpConfig config.HTTPProbe, logger *slog.Logger) ProbeResult {
	for _, headerMatchSpec := range httpConfig.FailIfHeaderMatchesRegexp {
		values := header[textproto.CanonicalMIMEHeaderKey(headerMatchSpec.Header)]
		if len(values) == 0 {
			if !headerMatchSpec.AllowMissing {
				return ProbeFailure("Missing required header", "header", headerMatchSpec.Header)
			} else {
				continue // No need to match any regex on missing headers.
			}
		}

		for _, val := range values {
			if headerMatchSpec.Regexp.MatchString(val) {
				return ProbeFailure("Header matched regular expression", "header", headerMatchSpec.Header,
					"regexp", headerMatchSpec.Regexp.String(), "value_count", strconv.Itoa(len(values)))
			}
		}
	}
	for _, headerMatchSpec := range httpConfig.FailIfHeaderNotMatchesRegexp {
		values := header[textproto.CanonicalMIMEHeaderKey(headerMatchSpec.Header)]
		if len(values) == 0 {
			if !headerMatchSpec.AllowMissing {
				return ProbeFailure("Missing required header", "header", headerMatchSpec.Header)
			} else {
				continue // No need to match any regex on missing headers.
			}
		}

		anyHeaderValueMatched := false

		for _, val := range values {
			if headerMatchSpec.Regexp.MatchString(val) {
				anyHeaderValueMatched = true
				break
			}
		}

		if !anyHeaderValueMatched {
			return ProbeFailure("Header did not match regular expression", "header", headerMatchSpec.Header,
				"regexp", headerMatchSpec.Regexp.String(), "value_count", strconv.Itoa(len(values)))
		}
	}

	return ProbeSuccess()
}

// roundTripTrace holds timings for a single HTTP roundtrip.
type roundTripTrace struct {
	tls           bool
	start         time.Time
	dnsDone       time.Time
	connectDone   time.Time
	gotConn       time.Time
	responseStart time.Time
	end           time.Time
	tlsStart      time.Time
	tlsDone       time.Time
}

// transport is a custom transport keeping traces for each HTTP roundtrip.
type transport struct {
	Transport             http.RoundTripper
	NoServerNameTransport http.RoundTripper
	firstHost             string
	logger                *slog.Logger

	mu      sync.Mutex
	traces  []*roundTripTrace
	current *roundTripTrace
}

func newTransport(rt, noServerName http.RoundTripper, logger *slog.Logger) *transport {
	return &transport{
		Transport:             rt,
		NoServerNameTransport: noServerName,
		logger:                logger,
		traces:                []*roundTripTrace{},
	}
}

// RoundTrip switches to a new trace, then runs embedded RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.logger.Info("Making HTTP request", "url", req.URL.String(), "host", req.Host)

	trace := &roundTripTrace{}
	if req.URL.Scheme == "https" {
		trace.tls = true
	}
	t.current = trace
	t.traces = append(t.traces, trace)

	if t.firstHost == "" {
		t.firstHost = req.URL.Host
	}

	if t.firstHost != req.URL.Host {
		// This is a redirect to something other than the initial host,
		// so TLS ServerName should not be set.
		t.logger.Info("Address does not match first address, not sending TLS ServerName", "first", t.firstHost, "address", req.URL.Host)
		return t.NoServerNameTransport.RoundTrip(req)
	}

	return t.Transport.RoundTrip(req)
}

func (t *transport) DNSStart(_ httptrace.DNSStartInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.start = time.Now()
}
func (t *transport) DNSDone(_ httptrace.DNSDoneInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.dnsDone = time.Now()
}
func (ts *transport) ConnectStart(_, _ string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := ts.current
	// No DNS resolution because we connected to IP directly.
	if t.dnsDone.IsZero() {
		t.start = time.Now()
		t.dnsDone = t.start
	}
}
func (t *transport) ConnectDone(net, addr string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.connectDone = time.Now()
}
func (t *transport) GotConn(_ httptrace.GotConnInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.gotConn = time.Now()
}
func (t *transport) GotFirstResponseByte() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.responseStart = time.Now()
}
func (t *transport) TLSHandshakeStart() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.tlsStart = time.Now()
}
func (t *transport) TLSHandshakeDone(_ tls.ConnectionState, _ error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.tlsDone = time.Now()
}

// byteCounter implements an io.ReadCloser that keeps track of the total
// number of bytes it has read.
type byteCounter struct {
	io.ReadCloser
	n int64
}

func (bc *byteCounter) Read(p []byte) (int, error) {
	n, err := bc.ReadCloser.Read(p)
	bc.n += int64(n)
	return n, err
}

var userAgentDefaultHeader = fmt.Sprintf("Blackbox Exporter/%s", version.Version)

func ProbeHTTP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (result ProbeResult) {
	var redirects int
	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_http_duration_seconds",
			Help: "Duration of http request by phase, summed over all redirects",
		}, []string{"phase"})
		contentLengthGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_content_length",
			Help: "Length of http content response",
		})
		bodyUncompressedLengthGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_uncompressed_body_length",
			Help: "Length of uncompressed response body",
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

		probeSSLEarliestCertExpiryGauge = prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)

		probeSSLLastChainExpiryTimestampSeconds = prometheus.NewGauge(sslChainExpiryInTimeStampGaugeOpts)

		probeSSLLastInformation = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probe_ssl_last_chain_info",
				Help: "Contains SSL leaf certificate information",
			},
			[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber"},
		)

		probeTLSVersion = prometheus.NewGaugeVec(
			probeTLSInfoGaugeOpts,
			[]string{"version"},
		)

		probeTLSCipher = prometheus.NewGaugeVec(
			probeTLSCipherGaugeOpts,
			[]string{"cipher"},
		)

		probeHTTPVersionGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_version",
			Help: "Returns the version of HTTP of the probe response",
		})

		probeFailedDueToRegex = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_regex",
			Help: "Indicates if probe failed due to regex",
		})

		probeFailedDueToCEL = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_cel",
			Help: "Indicates if probe failed due to CEL expression not matching",
		})

		probeHTTPLastModified = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_last_modified_timestamp_seconds",
			Help: "Returns the Last-Modified HTTP response header in unixtime",
		})
	)

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(contentLengthGauge)
	registry.MustRegister(bodyUncompressedLengthGauge)
	registry.MustRegister(redirectsGauge)
	registry.MustRegister(isSSLGauge)
	registry.MustRegister(statusCodeGauge)
	registry.MustRegister(probeHTTPVersionGauge)
	registry.MustRegister(probeFailedDueToRegex)

	httpConfig := module.HTTP

	if httpConfig.FailIfBodyJsonMatchesCEL != nil || httpConfig.FailIfBodyJsonNotMatchesCEL != nil {
		registry.MustRegister(probeFailedDueToCEL)
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Could not parse target URL")
	}

	targetHost := targetURL.Hostname()
	targetPort := targetURL.Port()

	var ip *net.IPAddr
	if !module.HTTP.SkipResolvePhaseWithProxy || module.HTTP.HTTPClientConfig.ProxyURL.URL == nil || module.HTTP.HTTPClientConfig.ProxyFromEnvironment {
		var lookupTime float64
		var resolveResult ProbeResult
		ip, lookupTime, resolveResult = chooseProtocol(ctx, module.HTTP.IPProtocol, module.HTTP.IPProtocolFallback, targetHost, registry, logger)
		durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)
		if !resolveResult.success {
			return resolveResult
		}
	}

	httpClientConfig := module.HTTP.HTTPClientConfig
	if len(httpClientConfig.TLSConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// the hostname of the target.
		httpClientConfig.TLSConfig.ServerName = targetHost

		// However, if there is a Host header it is better to use
		// its value instead. This helps avoid TLS handshake error
		// if targetHost is an IP address.
		for name, value := range httpConfig.Headers {
			if textproto.CanonicalMIMEHeaderKey(name) == "Host" {
				httpClientConfig.TLSConfig.ServerName = value
			}
		}
	}
	client, err := pconfig.NewClientFromConfig(httpClientConfig, "http_probe", pconfig.WithKeepAlivesDisabled())
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error generating HTTP client")
	}

	httpClientConfig.TLSConfig.ServerName = ""
	noServerName, err := pconfig.NewRoundTripperFromConfig(httpClientConfig, "http_probe", pconfig.WithKeepAlivesDisabled())
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error generating HTTP client without ServerName")
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		logger.Error(err.Error())
		return ProbeFailure("Error generating cookiejar")
	}
	client.Jar = jar

	// Inject transport that tracks traces for each redirect,
	// and does not set TLS ServerNames on redirect if needed.
	tt := newTransport(client.Transport, noServerName, logger)
	client.Transport = tt

	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		logger.Info("Received redirect", "location", r.Response.Header.Get("Location"))
		redirects = len(via)
		if redirects > 10 || !httpConfig.HTTPClientConfig.FollowRedirects {
			logger.Info("Not following redirect")
			return errors.New("don't follow redirects")
		}
		return nil
	}

	if httpConfig.Method == "" {
		httpConfig.Method = "GET"
	}

	origHost := targetURL.Host
	if ip != nil {
		// Replace the host field in the URL with the IP we resolved.
		if targetPort == "" {
			if strings.Contains(ip.String(), ":") {
				targetURL.Host = "[" + ip.String() + "]"
			} else {
				targetURL.Host = ip.String()
			}
		} else {
			targetURL.Host = net.JoinHostPort(ip.String(), targetPort)
		}
	}

	var body io.Reader
	var respBodyBytes int64

	// If a body is configured, add it to the request.
	if httpConfig.Body != "" {
		body = strings.NewReader(httpConfig.Body)
	}

	// If a body file is configured, add its content to the request.
	if httpConfig.BodyFile != "" {
		body_file, err := os.Open(httpConfig.BodyFile)
		if err != nil {
			logger.Error("Error creating request", "err", err)
			return
		}
		defer body_file.Close()
		body = body_file
	}

	request, err := http.NewRequest(httpConfig.Method, targetURL.String(), body)
	if err != nil {
		logger.Error("Error creating request", "err", err)
		return
	}
	request.Host = origHost
	request = request.WithContext(ctx)

	for key, value := range httpConfig.Headers {
		if textproto.CanonicalMIMEHeaderKey(key) == "Host" {
			request.Host = value
			continue
		}

		request.Header.Set(key, value)
	}

	_, hasUserAgent := request.Header["User-Agent"]
	if !hasUserAgent {
		request.Header.Set("User-Agent", userAgentDefaultHeader)
	}

	trace := &httptrace.ClientTrace{
		DNSStart:             tt.DNSStart,
		DNSDone:              tt.DNSDone,
		ConnectStart:         tt.ConnectStart,
		ConnectDone:          tt.ConnectDone,
		GotConn:              tt.GotConn,
		GotFirstResponseByte: tt.GotFirstResponseByte,
		TLSHandshakeStart:    tt.TLSHandshakeStart,
		TLSHandshakeDone:     tt.TLSHandshakeDone,
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))

	for _, lv := range []string{"connect", "tls", "processing", "transfer"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	resp, err := client.Do(request)
	// This is different from the usual err != nil you'd expect here because err won't be nil if redirects were
	// turned off. See https://github.com/golang/go/issues/3795
	//
	// If err == nil there should never be a case where resp is also nil, but better be safe than sorry, so check if
	// resp == nil first, and then check if there was an error.
	if resp == nil {
		resp = &http.Response{}
		if err != nil {
			logger.Error("Error for HTTP request", "err", err.Error())
			result = ProbeFailure("HTTP request failed")
			// no return here, since there are cases where an error here
			// might be acceptable after all.
		}
	} else {
		requestErrored := (err != nil)

		logger.Info("Received HTTP response", "status_code", resp.StatusCode)
		if len(httpConfig.ValidStatusCodes) != 0 {
			for _, code := range httpConfig.ValidStatusCodes {
				if resp.StatusCode == code {
					result = ProbeSuccess()
					break
				}
			}
			if !result.success {
				logger.Info("Valid status codes", "codes", httpConfig.ValidStatusCodes)
				result = ProbeFailure("Invalid HTTP response status code", "status_code", strconv.Itoa(resp.StatusCode))
			}
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			result = ProbeSuccess()
		} else {
			result = ProbeFailure("Invalid HTTP response status code, wanted 2xx", "status_code", strconv.Itoa(resp.StatusCode))
		}

		if result.success && (len(httpConfig.FailIfHeaderMatchesRegexp) > 0 || len(httpConfig.FailIfHeaderNotMatchesRegexp) > 0) {
			result = matchRegularExpressionsOnHeaders(resp.Header, httpConfig, logger)
			if result.success {
				probeFailedDueToRegex.Set(0)
			} else {
				probeFailedDueToRegex.Set(1)
			}
		}

		// Since the configuration specifies a compression algorithm, blindly treat the response body as a
		// compressed payload; if we cannot decompress it it's a failure because the configuration says we
		// should expect the response to be compressed in that way.
		if httpConfig.Compression != "" {
			dec, err := getDecompressionReader(httpConfig.Compression, resp.Body)
			if err != nil {
				logger.Error(err.Error())
				result = ProbeFailure("Failed to get decompressor for HTTP response body")
			} else if dec != nil {
				// Since we are replacing the original resp.Body with the decoder, we need to make sure
				// we close the original body. We cannot close it right away because the decompressor
				// might not have read it yet.
				defer func(c io.Closer) {
					err := c.Close()
					if err != nil {
						// At this point we cannot really do anything with this error, but log
						// it in case it contains useful information as to what's the problem.
						logger.Info("Error while closing response from server", "err", err)
					}
				}(resp.Body)

				resp.Body = dec
			}
		}

		// If there's a configured body_size_limit, wrap the body in the response in a http.MaxBytesReader.
		// This will read up to BodySizeLimit bytes from the body, and return an error if the response is
		// larger. It forwards the Close call to the original resp.Body to make sure the TCP connection is
		// correctly shut down. The limit is applied _after decompression_ if applicable.
		if httpConfig.BodySizeLimit > 0 {
			resp.Body = http.MaxBytesReader(nil, resp.Body, int64(httpConfig.BodySizeLimit))
		}

		byteCounter := &byteCounter{ReadCloser: resp.Body}

		if result.success && (len(httpConfig.FailIfBodyMatchesRegexp) > 0 || len(httpConfig.FailIfBodyNotMatchesRegexp) > 0) {
			result = matchRegularExpressions(byteCounter, httpConfig, logger)
			if result.success {
				probeFailedDueToRegex.Set(0)
			} else {
				probeFailedDueToRegex.Set(1)
			}
		}

		if result.success && (httpConfig.FailIfBodyJsonMatchesCEL != nil || httpConfig.FailIfBodyJsonNotMatchesCEL != nil) {
			result = matchCELExpressions(ctx, byteCounter, httpConfig, logger)
			if result.success {
				probeFailedDueToCEL.Set(0)
			} else {
				probeFailedDueToCEL.Set(1)
			}
		}

		if !requestErrored {
			_, err = io.Copy(io.Discard, byteCounter)
			if err != nil {
				logger.Error(err.Error())
				result = ProbeFailure("Failed to read HTTP response body")
			}

			respBodyBytes = byteCounter.n

			if err := byteCounter.Close(); err != nil {
				// We have already read everything we could from the server, maybe even uncompressed the
				// body. The error here might be either a decompression error or a TCP error. Log it in
				// case it contains useful information as to what's the problem.
				logger.Info("Error while closing response from server", "error", err.Error())
			}
		}

		// At this point body is fully read and we can write end time.
		tt.current.end = time.Now()

		// Check if there is a Last-Modified HTTP response header.
		if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
			registry.MustRegister(probeHTTPLastModified)
			probeHTTPLastModified.Set(float64(t.Unix()))
		}

		var httpVersionNumber float64
		httpVersionNumber, err = strconv.ParseFloat(strings.TrimPrefix(resp.Proto, "HTTP/"), 64)
		if err != nil {
			logger.Error("Error parsing version number from HTTP version", "err", err)
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
				result = ProbeFailure("Invalid HTTP version number", "version", resp.Proto)
			}
		}
	}

	tt.mu.Lock()
	defer tt.mu.Unlock()
	for i, trace := range tt.traces {
		logger.Info(
			"Response timings for roundtrip",
			"roundtrip", i,
			"start", trace.start,
			"dnsDone", trace.dnsDone,
			"connectDone", trace.connectDone,
			"gotConn", trace.gotConn,
			"responseStart", trace.responseStart,
			"tlsStart", trace.tlsStart,
			"tlsDone", trace.tlsDone,
			"end", trace.end,
		)
		// We get the duration for the first request from chooseProtocol.
		if i != 0 {
			durationGaugeVec.WithLabelValues("resolve").Add(trace.dnsDone.Sub(trace.start).Seconds())
		}
		// Continue here if we never got a connection because a request failed.
		if trace.gotConn.IsZero() {
			continue
		}
		if trace.tls {
			// dnsDone must be set if gotConn was set.
			durationGaugeVec.WithLabelValues("connect").Add(trace.connectDone.Sub(trace.dnsDone).Seconds())
			durationGaugeVec.WithLabelValues("tls").Add(trace.tlsDone.Sub(trace.tlsStart).Seconds())
		} else {
			durationGaugeVec.WithLabelValues("connect").Add(trace.gotConn.Sub(trace.dnsDone).Seconds())
		}

		// Continue here if we never got a response from the server.
		if trace.responseStart.IsZero() {
			continue
		}
		durationGaugeVec.WithLabelValues("processing").Add(trace.responseStart.Sub(trace.gotConn).Seconds())

		// Continue here if we never read the full response from the server.
		// Usually this means that request either failed or was redirected.
		if trace.end.IsZero() {
			continue
		}
		durationGaugeVec.WithLabelValues("transfer").Add(trace.end.Sub(trace.responseStart).Seconds())
	}

	if resp.TLS != nil {
		isSSLGauge.Set(float64(1))
		registry.MustRegister(probeSSLEarliestCertExpiryGauge, probeTLSVersion, probeTLSCipher, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
		probeSSLEarliestCertExpiryGauge.Set(float64(getEarliestCertExpiry(resp.TLS).Unix()))
		probeTLSVersion.WithLabelValues(getTLSVersion(resp.TLS)).Set(1)
		probeTLSCipher.WithLabelValues(getTLSCipher(resp.TLS)).Set(1)
		probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(resp.TLS).Unix()))
		probeSSLLastInformation.WithLabelValues(getFingerprint(resp.TLS), getSubject(resp.TLS), getIssuer(resp.TLS), getDNSNames(resp.TLS), getSerialNumber(resp.TLS)).Set(1)
		if httpConfig.FailIfSSL {
			result = ProbeFailure("Final request was over SSL")
		}
	} else if httpConfig.FailIfNotSSL && result.success {
		result = ProbeFailure("Final request was not over SSL")
	}

	statusCodeGauge.Set(float64(resp.StatusCode))
	contentLengthGauge.Set(float64(resp.ContentLength))
	bodyUncompressedLengthGauge.Set(float64(respBodyBytes))
	redirectsGauge.Set(float64(redirects))

	return
}

func getDecompressionReader(algorithm string, origBody io.ReadCloser) (io.ReadCloser, error) {
	switch strings.ToLower(algorithm) {
	case "br":
		return io.NopCloser(brotli.NewReader(origBody)), nil

	case "deflate":
		return flate.NewReader(origBody), nil

	case "gzip":
		return gzip.NewReader(origBody)

	case "identity", "":
		return origBody, nil

	default:
		return nil, errors.New("unsupported compression algorithm")
	}
}
