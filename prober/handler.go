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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"time"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/promslog"
	"go.yaml.in/yaml/v2"
)

var (
	Probers = map[string]ProbeFn{
		"http": ProbeHTTP,
		"tcp":  ProbeTCP,
		"icmp": ProbeICMP,
		"dns":  ProbeDNS,
		"grpc": ProbeGRPC,
		"unix": ProbeUnix,
	}
)

func Handler(w http.ResponseWriter, r *http.Request, c *config.Config, logger *slog.Logger, rh *ResultHistory, timeoutOffset float64, params url.Values,
	moduleUnknownCounter prometheus.Counter,
	promslogConfig *promslog.Config) {

	if params == nil {
		params = r.URL.Query()
	}
	moduleName := params.Get("module")
	if moduleName == "" {
		moduleName = "http_2xx"
	}
	module, ok := c.Modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
		logger.Debug("Unknown module", "module", moduleName)
		if moduleUnknownCounter != nil {
			moduleUnknownCounter.Add(1)
		}
		return
	}

	timeoutSeconds, err := getTimeout(r, module, timeoutOffset)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse timeout from Prometheus header: %s", err), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSeconds*float64(time.Second)))
	defer cancel()
	r = r.WithContext(ctx)

	probeSuccessGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})
	probeDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})

	target := params.Get("target")
	if target == "" {
		http.Error(w, "Target parameter is missing", http.StatusBadRequest)
		return
	}

	prober, ok := Probers[module.Prober]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown prober %q", module.Prober), http.StatusBadRequest)
		return
	}

	hostname := params.Get("hostname")
	if module.Prober == "http" && hostname != "" {
		err = setHTTPHost(hostname, &module)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if module.Prober == "tcp" && hostname != "" {
		if module.TCP.TLSConfig.ServerName == "" {
			module.TCP.TLSConfig.ServerName = hostname
		}
	}

	sl := newScrapeLogger(promslogConfig, moduleName, target)
	slLogger := slog.New(sl)

	slLogger.Debug("Beginning probe", "probe", module.Prober, "timeout_seconds", timeoutSeconds)

	start := time.Now()
	registry := prometheus.NewRegistry()
	registry.MustRegister(probeSuccessGauge)
	registry.MustRegister(probeDurationGauge)
	success := prober(ctx, target, module, registry, slLogger)
	duration := time.Since(start).Seconds()
	probeDurationGauge.Set(duration)
	if success {
		probeSuccessGauge.Set(1)
		slLogger.Debug("Probe succeeded", "duration_seconds", duration)
	} else {
		slLogger.Error("Probe failed", "duration_seconds", duration)
	}

	debugOutput := DebugOutput(&module, sl.buffer, registry)
	rh.Add(moduleName, target, debugOutput, success)

	if r.URL.Query().Get("debug") == "true" {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(debugOutput))
		return
	}

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func setHTTPHost(hostname string, module *config.Module) error {
	// By creating a new hashmap and copying values there we
	// ensure that the initial configuration remain intact.
	headers := make(map[string]string)
	if module.HTTP.Headers != nil {
		for name, value := range module.HTTP.Headers {
			if textproto.CanonicalMIMEHeaderKey(name) == "Host" && value != hostname {
				return fmt.Errorf("host header defined both in module configuration (%s) and with URL-parameter 'hostname' (%s)", value, hostname)
			}
			headers[name] = value
		}
	}
	headers["Host"] = hostname
	module.HTTP.Headers = headers
	return nil
}

type scrapeLogger struct {
	next         *slog.Logger
	buffer       *bytes.Buffer
	bufferLogger *slog.Logger
	config       *promslog.Config
}

// Enabled returns true if both A) the scrapeLogger's internal `next` logger
// and B) the scrapeLogger's internal `bufferLogger` are enabled at the
// provided context/log level, and returns false otherwise. It implements
// slog.Handler.
func (sl *scrapeLogger) Enabled(ctx context.Context, level slog.Level) bool {
	nextEnabled := sl.next.Enabled(ctx, level)
	bufEnabled := sl.bufferLogger.Enabled(ctx, level)

	return nextEnabled && bufEnabled
}

// Handle writes the provided log record to the internal logger, and then to
// the internal bufferLogger for use with serving debug output. It implements
// slog.Handler.
func (sl *scrapeLogger) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	rec := r.Clone()

	// Scrape logger should only write to next, the "real" logger, if next
	// is enabled to write at the level the `--log.prober` flag is set to.
	if sl.next.Enabled(context.Background(), sl.config.Level.Level()) {
		errs = append(errs, sl.next.Handler().Handle(ctx, rec))
	}

	// Always log to the bufferLogger, this is used to retain scrape log
	// output for the `debug` URL param.
	errs = append(errs, sl.bufferLogger.Handler().Handle(ctx, rec))

	return errors.Join(errs...)
}

// WithAttrs adds the provided attributes to the scrapeLogger's internal logger and
// bufferLogger. It implements slog.Handler.
func (sl *scrapeLogger) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &scrapeLogger{
		next:         slog.New(sl.next.Handler().WithAttrs(attrs)),
		buffer:       sl.buffer,
		bufferLogger: slog.New(sl.bufferLogger.Handler().WithAttrs(attrs)),
		config:       sl.config,
	}
}

// WithGroup adds the provided group name to the scrapeLogger's internal logger
// and bufferLogger. It implements slog.Handler.
func (sl *scrapeLogger) WithGroup(name string) slog.Handler {
	return &scrapeLogger{
		next:         slog.New(sl.next.Handler().WithGroup(name)),
		buffer:       sl.buffer,
		bufferLogger: slog.New(sl.bufferLogger.Handler().WithGroup(name)),
		config:       sl.config,
	}
}

func newScrapeLogger(config *promslog.Config, module string, target string) *scrapeLogger {
	// The base logger that will write to stderr like usual.
	l := promslog.New(config)

	// The buffer logger, which uses the same promslog.Config and writes to
	// a bytes.Buffer for retrieval when using the `debug` URL param.
	var buf bytes.Buffer
	bl := promslog.New(&promslog.Config{
		Writer: &buf,
		Level:  config.Level,
		Format: config.Format,
		Style:  config.Style,
	})

	sl := &scrapeLogger{
		next:         l.With("module", module, "target", target),
		buffer:       &buf,
		bufferLogger: bl.With("module", module, "target", target),
		config:       config,
	}
	return sl
}

// DebugOutput returns plaintext debug output for a probe.
func DebugOutput(module *config.Module, logBuffer *bytes.Buffer, registry *prometheus.Registry) string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Logs for the probe:\n")
	logBuffer.WriteTo(buf)
	fmt.Fprintf(buf, "\n\n\nMetrics that would have been returned:\n")
	mfs, err := registry.Gather()
	if err != nil {
		fmt.Fprintf(buf, "Error gathering metrics: %s\n", err)
	}
	for _, mf := range mfs {
		expfmt.MetricFamilyToText(buf, mf)
	}
	fmt.Fprintf(buf, "\n\n\nModule configuration:\n")
	c, err := yaml.Marshal(module)
	if err != nil {
		fmt.Fprintf(buf, "Error marshalling config: %s\n", err)
	}
	buf.Write(c)

	return buf.String()
}

func getTimeout(r *http.Request, module config.Module, offset float64) (timeoutSeconds float64, err error) {
	// If a timeout is configured via the Prometheus header, add it to the request.
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		var err error
		timeoutSeconds, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, err
		}
	}
	if timeoutSeconds == 0 {
		timeoutSeconds = 120
	}

	var maxTimeoutSeconds = timeoutSeconds - offset
	if module.Timeout.Seconds() < maxTimeoutSeconds && module.Timeout.Seconds() > 0 || maxTimeoutSeconds < 0 {
		timeoutSeconds = module.Timeout.Seconds()
	} else {
		timeoutSeconds = maxTimeoutSeconds
	}

	return timeoutSeconds, nil
}
