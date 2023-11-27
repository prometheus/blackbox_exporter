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

package discovery

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	discoveryCount = promauto.With(prometheus.DefaultRegisterer).NewCounter(prometheus.CounterOpts{
		Namespace: "blackbox_exporter",
		Subsystem: "discovery",
		Name:      "count",
		Help:      "Displays count of discoveries",
	})
	discoveryErrors = promauto.With(prometheus.DefaultRegisterer).NewCounterVec(prometheus.CounterOpts{
		Namespace: "blackbox_exporter",
		Subsystem: "discovery",
		Name:      "errors",
		Help:      "Displays count of discovery errors",
	},
		[]string{"file", "module"})
)

func Handler(w http.ResponseWriter, r *http.Request, path string, c *config.Config, logger log.Logger) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(float64(10*time.Second)))
	defer cancel()
	r = r.WithContext(ctx)

	discoveryCount.Inc()

	ds := c.Discoveries.Configs

	df := getDiscoveriesFromFiles(c.Discoveries.Files, logger)
	if df != nil {
		ds = append(ds, df...)
	}

	comma := false
	host := "localhost"
	path = strings.TrimRight(path, "/")
	port := "9115"
	if strings.Contains(r.Host, ":") {
		host = strings.Split(r.Host, ":")[0]
		port = strings.Split(r.Host, ":")[1]
	} else if r.Host != "" {
		host = r.Host
	}
	scheme := "http"
	dest := host + ":" + port
	if r.TLS != nil {
		scheme = "https"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`[`))
	for _, d := range ds {
		if _, ok := c.Modules[d.Module]; !ok {
			discoveryErrors.WithLabelValues(d.Filename, d.Module).Inc()
			level.Debug(logger).Log("msg", "Unknown module in discovery", "module", d.Module, "file", d.Filename)
			continue
		}
		for _, t := range d.Targets {
			if comma {
				w.Write([]byte(`,`))
			} else {
				comma = true
			}
			writeTarget(w, scheme, dest, path, t, d)
		}
	}
	w.Write([]byte(`]`))
}

func getDiscoveriesFromFiles(files []string, logger log.Logger) []*config.Discovery {
	d := make([]*config.Discovery, 0)
	for _, file := range files {
		ds, err := yamlDiscoveryFile(file, logger)
		if err == nil {
			d = append(d, ds...)
		}
	}
	return d
}

func yamlDiscoveryFile(file string, logger log.Logger) ([]*config.Discovery, error) {
	d := make([]*config.Discovery, 0)
	yamlReader, err := os.Open(file)
	if err != nil {
		discoveryErrors.WithLabelValues(file, "").Inc()
		level.Debug(logger).Log("msg", "Unable to open discovery file", "file", file)
		return nil, err
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)

	err = decoder.Decode(&d)
	if err != nil {
		discoveryErrors.WithLabelValues(file, "").Inc()
		level.Debug(logger).Log("msg", "Discovery file is not valid yaml", "file", file)
		return nil, err
	}
	for _, e := range d {
		e.Filename = file
	}
	return d, nil
}

func writeTarget(w http.ResponseWriter, scheme string, dest string, path string, target string, d *config.Discovery) {
	w.Write([]byte(`{"targets": ["` + dest + `"],`))
	w.Write([]byte(`"labels":{"__scheme__":"` + scheme + `"`))
	w.Write([]byte(`,"__metrics_path__":"` + path + `/probe"`))
	w.Write([]byte(`,"__param_module":"` + d.Module + `"`))
	w.Write([]byte(`,"__param_target":"` + target + `"`))
	if d.Hostname != nil {
		w.Write([]byte(`,__param_hostname":"` + *d.Hostname + `"`))
	}
	if d.ScrapeInterval != nil {
		w.Write([]byte(`,__scrape_interval__":"` + d.ScrapeInterval.String() + `"`))
	}
	if d.ScrapeTimeout != nil {
		w.Write([]byte(`,__scrape_timeout__":"` + d.ScrapeInterval.String() + `"`))
	}
	w.Write([]byte(`}}`))
}
