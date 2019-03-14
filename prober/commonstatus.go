package prober

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/prometheus/util/promlint"
	"golang.org/x/net/publicsuffix"
)

func isValidMetric(metric []byte) bool {
	l := promlint.New(bytes.NewReader(append(metric, '\n')))
	if _, err := l.Lint(); err != nil {
		return false
	}
	return true
}

func createPrometheusMetricFin(name string, desc string, labels prometheus.Labels, value float64, metricType prometheus.ValueType, registry *prometheus.Registry) error {
	invalidChars := regexp.MustCompile("[^a-zA-Z0-9:_]")
	name = invalidChars.ReplaceAllLiteralString(name, "_")

	var err error
	switch metricType {
	case prometheus.GaugeValue:
		metric := prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        name,
			Help:        desc,
			ConstLabels: labels,
		})
		err = registry.Register(metric)
		metric.Set(value)
	case prometheus.CounterValue:
		metric := prometheus.NewCounter(prometheus.CounterOpts{
			Name:        name,
			Help:        desc,
			ConstLabels: labels,
		})
		err = registry.Register(metric)
		metric.Add(value)
	}

	return err
}

func createPrometheusMetric(name string, desc string, value string, metricType prometheus.ValueType, registry *prometheus.Registry) error {
	invalidChars := regexp.MustCompile("[^a-zA-Z0-9:_]")
	name = invalidChars.ReplaceAllLiteralString(name, "_")

	floatValue, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fmt.Errorf("can't parse: %v to float", value)
	}

	return createPrometheusMetricFin(name, desc, nil, floatValue, metricType, registry)
}

func createInfoMetric(infoLabels *prometheus.Labels, registry *prometheus.Registry) error {
	return createPrometheusMetricFin("commonstatus_info", "commonstatus information", *infoLabels, float64(1), prometheus.GaugeValue, registry)
}

func parseReleaseTag(metric []byte, infoLabels *prometheus.Labels) error {
	re := regexp.MustCompile(`^ReleaseTag: (.*)$`)

	if !re.Match(metric) {
		return fmt.Errorf("the metric doesn't contain a ReleaseTag: %s", metric)
	}

	releaseTag := string(re.FindSubmatch(metric)[1])
	(*infoLabels)["release_tag"] = releaseTag

	return nil
}

func convertLoadAvg(metric []byte, registry *prometheus.Registry) error {
	re := regexp.MustCompile(`^LoadAvg: (?P<la1m>\d+(\.\d+)?) (?P<la5m>\d+(\.\d+)?) (?P<la15m>\d+(\.\d+)?)$`)

	if !(re.Match(metric)) {
		return fmt.Errorf("no LoadAvg metric found in: %s", metric)
	}

	matchResult := re.FindSubmatch(metric)

	err := createPrometheusMetric("load_avertage1", "1m load average.", string(matchResult[1]), prometheus.GaugeValue, registry)
	if err != nil {
		return err
	}

	err = createPrometheusMetric("load_avertage5", "5m load average.", string(matchResult[3]), prometheus.GaugeValue, registry)
	if err != nil {
		return err
	}

	return createPrometheusMetric("load_avertage15", "15m load average.", string(matchResult[5]), prometheus.GaugeValue, registry)
}

func convertNumberSeparators(metric []byte, registry *prometheus.Registry) error {
	re := regexp.MustCompile(`^([a-zA-Z_:]([a-zA-Z0-9_:])*): ([0-9]+([0-9,.])*[0-9]*)$`)

	if !(re.Match(metric)) {
		return fmt.Errorf("no metric with numberic value found in: %s", metric)
	}

	name := re.FindSubmatch(metric)[1]
	value := re.FindSubmatch(metric)[3]

	re = regexp.MustCompile(`^[0-9]([0-9,])+[0-9]$`)
	if re.Match(value) {
		value = bytes.Replace(value, []byte(","), []byte("."), -1)
	}

	re = regexp.MustCompile(`^[0-9]+(\.[0-9]+){2,}$`)
	if re.Match(value) {
		resultValue := bytes.Replace(value, []byte("."), []byte(""), -1)
		err := createPrometheusMetric(string(name), "", string(resultValue), prometheus.GaugeValue, registry)
		if err != nil {
			return err
		}
		return nil
	}

	re = regexp.MustCompile(`^[0-9]+(.[0-9]+)+,[0-9]+$`)
	if re.Match(value) {
		value = bytes.Replace(value, []byte("."), []byte(""), -1)
		value = bytes.Replace(value, []byte(","), []byte("."), -1)
		err := createPrometheusMetric(string(name), "", string(value), prometheus.GaugeValue, registry)
		if err != nil {
			return err
		}
		return nil
	}

	re = regexp.MustCompile(`^[0-9]+(,[0-9]+)+.[0-9]+$`)
	if re.Match(value) {
		value = bytes.Replace(value, []byte(","), []byte(""), -1)
		err := createPrometheusMetric(string(name), "", string(value), prometheus.GaugeValue, registry)
		if err != nil {
			return err
		}
		return nil
	}

	return createPrometheusMetric(string(name), "", string(value), prometheus.GaugeValue, registry)
}

func convertStartupTime(metric []byte, registry *prometheus.Registry) error {
	re := regexp.MustCompile(`^StartupTime: (.*)$`)

	if !(re.Match(metric)) {
		return fmt.Errorf("no metric with numberic value found in: %s", metric)
	}

	value := re.FindSubmatch(metric)[1]

	parsedTime, err := time.Parse(time.UnixDate, string(value))
	if err != nil {
		return err
	}
	uptime := time.Since(parsedTime).Seconds()

	return createPrometheusMetricFin("app_uptime_seconds_total", "Time that an application is running", nil, uptime, prometheus.CounterValue, registry)
}

func createMetric(metric []byte, registry *prometheus.Registry) error {
	re := regexp.MustCompile(`^([a-zA-Z_:]([a-zA-Z0-9_:])*): (.*)$`)
	if !re.Match(metric) {
		return fmt.Errorf("the string doesn't contain a valid metric: %s", metric)
	}

	name := string(re.FindSubmatch(metric)[1])
	value := string(re.FindSubmatch(metric)[3])

	return createPrometheusMetric(name, "", value, prometheus.GaugeValue, registry)
}

func convertMetric(metric []byte, registry *prometheus.Registry) error {
	re := regexp.MustCompile(`^([a-zA-Z_:]([a-zA-Z0-9_:])*): .*$`)
	if !re.Match(metric) {
		return fmt.Errorf("the string doesn't contain a valid metric: %s", metric)
	}

	infoLabels := make(prometheus.Labels)
	if err := parseReleaseTag(metric, &infoLabels); err == nil {
		return createInfoMetric(&infoLabels, registry)
	}

	if err := convertLoadAvg(metric, registry); err == nil {
		return nil
	}

	if err := convertNumberSeparators(metric, registry); err == nil {
		return nil
	}

	if err := convertStartupTime(metric, registry); err == nil {
		return nil
	}

	return fmt.Errorf("Can't convert metric: %s. No suitable conversion function found", metric)
}

func convertMetrics(reader io.Reader, registry *prometheus.Registry, logger log.Logger) bool {
	var converted, failed int
	var (
		convertedMetricsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_commonstatus_converted_metrics",
			Help: "The number of CommonStatus metrics converted to prometheus metrics",
		})
		failedMetricsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_commonstatus_failed_metrics",
			Help: "The number of CommonStatus metrics failed to convert to prometheus metrics",
		})
	)

	registry.MustRegister(convertedMetricsGauge)
	registry.MustRegister(failedMetricsGauge)

	body, err := ioutil.ReadAll(reader)
	if err != nil {
		level.Error(logger).Log("msg", "Error reading HTTP body", "err", err)
		return false
	}

	for _, line := range bytes.Split(body, []byte{'\n'}) {
		if isValidMetric(line) && len(line) > 0 {
			if err := createMetric(line, registry); err != nil {
				level.Error(logger).Log("Failed to add valid metric", line, "error", err)
				failed++
				continue
			}
			level.Debug(logger).Log("Added metric to the registry!", "metric", line)
			converted++
		} else {
			level.Debug(logger).Log("Metric is not valid, trying to convert it", "metric", line)
			err := convertMetric(line, registry)
			if err != nil {
				level.Debug(logger).Log("Failed to convert metric", line, "error", err)
				failed++
			} else {
				level.Debug(logger).Log("Converted and added metric", line)
				converted++
			}
		}
	}
	convertedMetricsGauge.Set(float64(converted))
	failedMetricsGauge.Set(float64(failed))
	return true
}

func ProbeCommonStatus(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var redirects int
	var (
		contentLengthGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_commonstatus_content_length",
			Help: "Length of http content response",
		})

		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_commonstatus_duration_seconds",
			Help: "Duration of http request by phase, summed over all redirects",
		}, []string{"phase"})

		redirectsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_commonstatus_redirects",
			Help: "The number of redirects",
		})

		statusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_commonstatus_status_code",
			Help: "Response HTTP status code",
		})
	)

	for _, lv := range []string{"resolve", "connect", "tls", "processing", "transfer"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(contentLengthGauge)
	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(redirectsGauge)
	registry.MustRegister(statusCodeGauge)

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

	ip, lookupTime, err := chooseProtocol(module.HTTP.IPProtocol, module.HTTP.IPProtocolFallback, targetHost, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)

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

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		level.Error(logger).Log("msg", "Error generating cookiejar", "err", err)
		return false
	}
	client.Jar = jar

	// Inject transport that tracks trace for each redirect.
	tt := newTransport(client.Transport, logger)
	client.Transport = tt

	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		level.Info(logger).Log("msg", "Received redirect", "url", r.URL.String())
		redirects = len(via)
		if redirects > 10 || httpConfig.NoFollowRedirects {
			level.Info(logger).Log("msg", "Not following redirect")
			return errors.New("don't follow redirects")
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

	var body io.Reader

	// If a body is configured, add it to the request.
	if httpConfig.Body != "" {
		body = strings.NewReader(httpConfig.Body)
	}

	request, err := http.NewRequest(httpConfig.Method, targetURL.String(), body)
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

	level.Info(logger).Log("msg", "Making HTTP request", "url", request.URL.String(), "host", request.Host)

	trace := &httptrace.ClientTrace{
		DNSStart:             tt.DNSStart,
		DNSDone:              tt.DNSDone,
		ConnectStart:         tt.ConnectStart,
		ConnectDone:          tt.ConnectDone,
		GotConn:              tt.GotConn,
		GotFirstResponseByte: tt.GotFirstResponseByte,
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))

	resp, err := client.Do(request)
	// Err won't be nil if redirects were turned off. See https://github.com/golang/go/issues/3795
	if err != nil {
		level.Error(logger).Log("msg", "Error for HTTP request", "err", err)
	} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
		level.Info(logger).Log("msg", "Received HTTP response", "status_code", resp.StatusCode)
		success = convertMetrics(resp.Body, registry, logger)
		resp.Body.Close()
	} else {
		level.Error(logger).Log("msg", "Invalid HTTP response status code, wanted 2xx", "status_code", resp.StatusCode)
	}

	// At this point body is fully read and we can write end time.
	tt.current.end = time.Now()
	for i, trace := range tt.traces {
		level.Info(logger).Log(
			"msg", "Response timings for roundtrip",
			"roundtrip", i,
			"start", trace.start,
			"dnsDone", trace.dnsDone,
			"connectDone", trace.connectDone,
			"gotConn", trace.gotConn,
			"responseStart", trace.responseStart,
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
			durationGaugeVec.WithLabelValues("tls").Add(trace.gotConn.Sub(trace.dnsDone).Seconds())
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

	statusCodeGauge.Set(float64(resp.StatusCode))
	contentLengthGauge.Set(float64(resp.ContentLength))
	redirectsGauge.Set(float64(redirects))

	return
}
