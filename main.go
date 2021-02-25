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
	"bytes"
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v3"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/prober"
)

var (
	sc = &config.SafeConfig{
		C: &config.Config{},
	}

	configFile    = kingpin.Flag("config.file", "Blackbox exporter configuration file.").Default("blackbox.yml").String()
	webConfig     = webflag.AddFlags(kingpin.CommandLine)
	listenAddress = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(":9115").String()
	timeoutOffset = kingpin.Flag("timeout-offset", "Offset to subtract from timeout in seconds.").Default("0.5").Float64()
	configCheck   = kingpin.Flag("config.check", "If true validate the config file and then exit.").Default().Bool()
	historyLimit  = kingpin.Flag("history.limit", "The maximum amount of items to keep in the history.").Default("100").Uint()
	externalURL   = kingpin.Flag("web.external-url", "The URL under which Blackbox exporter is externally reachable (for example, if Blackbox exporter is served via a reverse proxy). Used for generating relative and absolute links back to Blackbox exporter itself. If the URL has a path portion, it will be used to prefix all HTTP endpoints served by Blackbox exporter. If omitted, relevant URL components will be derived automatically.").PlaceHolder("<url>").String()
	routePrefix   = kingpin.Flag("web.route-prefix", "Prefix for the internal routes of web endpoints. Defaults to path of --web.external-url.").PlaceHolder("<path>").String()

	Probers = map[string]prober.ProbeFn{
		"http": prober.ProbeHTTP,
		"tcp":  prober.ProbeTCP,
		"icmp": prober.ProbeICMP,
		"dns":  prober.ProbeDNS,
	}

	moduleUnknownCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blackbox_module_unknown_total",
		Help: "Count of unknown modules requested by probes",
	})
)

func probeHandler(w http.ResponseWriter, r *http.Request, c *config.Config, logger log.Logger, rh *resultHistory) {
	moduleName := r.URL.Query().Get("module")
	if moduleName == "" {
		moduleName = "http_2xx"
	}
	module, ok := c.Modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
		level.Debug(logger).Log("msg", "Unknown module", "module", moduleName)
		moduleUnknownCounter.Add(1)
		return
	}

	timeoutSeconds, err := getTimeout(r, module, *timeoutOffset)
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

	params := r.URL.Query()
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

	sl := newScrapeLogger(logger, moduleName, target)
	level.Info(sl).Log("msg", "Beginning probe", "probe", module.Prober, "timeout_seconds", timeoutSeconds)

	start := time.Now()
	registry := prometheus.NewRegistry()
	registry.MustRegister(probeSuccessGauge)
	registry.MustRegister(probeDurationGauge)
	success := prober(ctx, target, module, registry, sl)
	duration := time.Since(start).Seconds()
	probeDurationGauge.Set(duration)
	if success {
		probeSuccessGauge.Set(1)
		level.Info(sl).Log("msg", "Probe succeeded", "duration_seconds", duration)
	} else {
		level.Error(sl).Log("msg", "Probe failed", "duration_seconds", duration)
	}

	debugOutput := DebugOutput(&module, &sl.buffer, registry)
	rh.Add(moduleName, target, debugOutput, success)

	if r.URL.Query().Get("debug") == "true" {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(debugOutput))
		return
	}

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

type scrapeLogger struct {
	next         log.Logger
	buffer       bytes.Buffer
	bufferLogger log.Logger
}

func newScrapeLogger(logger log.Logger, module string, target string) *scrapeLogger {
	logger = log.With(logger, "module", module, "target", target)
	sl := &scrapeLogger{
		next:   logger,
		buffer: bytes.Buffer{},
	}
	bl := log.NewLogfmtLogger(&sl.buffer)
	sl.bufferLogger = log.With(bl, "ts", log.DefaultTimestampUTC, "caller", log.Caller(6), "module", module, "target", target)
	return sl
}

func (sl scrapeLogger) Log(keyvals ...interface{}) error {
	sl.bufferLogger.Log(keyvals...)
	kvs := make([]interface{}, len(keyvals))
	copy(kvs, keyvals)
	// Switch level to debug for application output.
	for i := 0; i < len(kvs); i += 2 {
		if kvs[i] == level.Key() {
			kvs[i+1] = level.DebugValue()
		}
	}
	return sl.next.Log(kvs...)
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

func init() {
	prometheus.MustRegister(version.NewCollector("blackbox_exporter"))
	prometheus.MustRegister(moduleUnknownCounter)
}

func main() {
	os.Exit(run())
}

func run() int {
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("blackbox_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)
	rh := &resultHistory{maxResults: *historyLimit}

	level.Info(logger).Log("msg", "Starting blackbox_exporter", "version", version.Info())
	level.Info(logger).Log("build_context", version.BuildContext())

	if err := sc.ReloadConfig(*configFile); err != nil {
		level.Error(logger).Log("msg", "Error loading config", "err", err)
		return 1
	}

	if *configCheck {
		level.Info(logger).Log("msg", "Config file is ok exiting...")
		return 0
	}

	level.Info(logger).Log("msg", "Loaded config file")

	// Infer or set Blackbox exporter externalURL
	beURL, err := computeExternalURL(*externalURL, *listenAddress)
	if err != nil {
		level.Error(logger).Log("msg", "failed to determine external URL", "err", err)
		return 1
	}
	level.Debug(logger).Log("externalURL", beURL.String())

	// Default -web.route-prefix to path of -web.external-url.
	if *routePrefix == "" {
		*routePrefix = beURL.Path
	}

	// routePrefix must always be at least '/'.
	*routePrefix = "/" + strings.Trim(*routePrefix, "/")
	// routePrefix requires path to have trailing "/" in order
	// for browsers to interpret the path-relative path correctly, instead of stripping it.
	if *routePrefix != "/" {
		*routePrefix = *routePrefix + "/"
	}
	level.Debug(logger).Log("routePrefix", *routePrefix)

	hup := make(chan os.Signal, 1)
	reloadCh := make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					continue
				}
				level.Info(logger).Log("msg", "Reloaded config file")
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					rc <- err
				} else {
					level.Info(logger).Log("msg", "Reloaded config file")
					rc <- nil
				}
			}
		}
	}()

	// Match Prometheus behaviour and redirect over externalURL for root path only
	// if routePrefix is different than "/"
	if *routePrefix != "/" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, beURL.String(), http.StatusFound)
		})
	}

	http.HandleFunc(path.Join(*routePrefix, "/-/reload"),
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprintf(w, "This endpoint requires a POST request.\n")
				return
			}

			rc := make(chan error)
			reloadCh <- rc
			if err := <-rc; err != nil {
				http.Error(w, fmt.Sprintf("failed to reload config: %s", err), http.StatusInternalServerError)
			}
		})
	http.Handle(path.Join(*routePrefix, "/metrics"), promhttp.Handler())
	http.HandleFunc(path.Join(*routePrefix, "/-/healthy"), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Healthy"))
	})
	http.HandleFunc(path.Join(*routePrefix, "/probe"), func(w http.ResponseWriter, r *http.Request) {
		sc.Lock()
		conf := sc.C
		sc.Unlock()
		probeHandler(w, r, conf, logger, rh)
	})
	http.HandleFunc(*routePrefix, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html>
    <head><title>Blackbox Exporter</title></head>
    <body>
    <h1>Blackbox Exporter</h1>
    <p><a href="probe?target=prometheus.io&module=http_2xx">Probe prometheus.io for http_2xx</a></p>
    <p><a href="probe?target=prometheus.io&module=http_2xx&debug=true">Debug probe prometheus.io for http_2xx</a></p>
    <p><a href="metrics">Metrics</a></p>
    <p><a href="config">Configuration</a></p>
    <h2>Recent Probes</h2>
    <table border='1'><tr><th>Module</th><th>Target</th><th>Result</th><th>Debug</th>`))

		results := rh.List()

		for i := len(results) - 1; i >= 0; i-- {
			r := results[i]
			success := "Success"
			if !r.success {
				success = "<strong>Failure</strong>"
			}
			fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td><a href='logs?id=%d'>Logs</a></td></td>",
				html.EscapeString(r.moduleName), html.EscapeString(r.target), success, r.id)
		}

		w.Write([]byte(`</table></body>
    </html>`))
	})

	http.HandleFunc(path.Join(*routePrefix, "/logs"), func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil {
			http.Error(w, "Invalid probe id", 500)
			return
		}
		result := rh.Get(id)
		if result == nil {
			http.Error(w, "Probe id not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(result.debugOutput))
	})

	http.HandleFunc(path.Join(*routePrefix, "/config"), func(w http.ResponseWriter, r *http.Request) {
		sc.RLock()
		c, err := yaml.Marshal(sc.C)
		sc.RUnlock()
		if err != nil {
			level.Warn(logger).Log("msg", "Error marshalling configuration", "err", err)
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(c)
	})

	srv := &http.Server{Addr: *listenAddress}
	srvc := make(chan struct{})
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	go func() {
		level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
		if err := web.ListenAndServe(srv, *webConfig, logger); err != http.ErrServerClosed {
			level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
			close(srvc)
		}
	}()

	for {
		select {
		case <-term:
			level.Info(logger).Log("msg", "Received SIGTERM, exiting gracefully...")
			return 0
		case <-srvc:
			return 1
		}
	}

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
	if module.Timeout.Seconds() < maxTimeoutSeconds && module.Timeout.Seconds() > 0 {
		timeoutSeconds = module.Timeout.Seconds()
	} else {
		timeoutSeconds = maxTimeoutSeconds
	}

	return timeoutSeconds, nil
}

func startsOrEndsWithQuote(s string) bool {
	return strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") ||
		strings.HasSuffix(s, "\"") || strings.HasSuffix(s, "'")
}

// computeExternalURL computes a sanitized external URL from a raw input. It infers unset
// URL parts from the OS and the given listen address.
func computeExternalURL(u, listenAddr string) (*url.URL, error) {
	if u == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		_, port, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("http://%s:%s/", hostname, port)
	}

	if startsOrEndsWithQuote(u) {
		return nil, errors.New("URL must not begin or end with quotes")
	}

	eu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	ppref := strings.TrimRight(eu.Path, "/")
	if ppref != "" && !strings.HasPrefix(ppref, "/") {
		ppref = "/" + ppref
	}
	eu.Path = ppref

	return eu, nil
}
