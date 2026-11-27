// Copyright The Prometheus Authors
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

//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// probeCase becomes its own exporter module, named by moduleName.
type probeCase struct {
	prober string
	name   string
	// exporter names the exporter container the case runs on. Empty means the default exporter.
	// Cases with the same exporter name share one container, so they must have the same dockerArgs.
	exporter string
	// dockerArgs are extra docker run arguments for the exporter container.
	dockerArgs []string
	target     string
	// YAML of the prober's section.
	module string
	want   float64
	// Proves the case passed or failed for the intended reason.
	wantLog string
	metrics []metricWant
}

func (c probeCase) moduleName() string {
	return c.prober + "_" + strings.ReplaceAll(c.name, " ", "_")
}

type metricWant struct {
	name   string
	labels map[string]string
	value  float64
}

func moduleConfig(cases []probeCase) ([]byte, error) {
	// The exporter tests probe it.
	modules := map[string]any{"http_2xx": map[string]any{"prober": "http", "timeout": "5s"}}
	for _, c := range cases {
		name := c.moduleName()
		if _, ok := modules[name]; ok {
			return nil, fmt.Errorf("duplicate module %s", name)
		}
		section := map[string]any{}
		if err := yaml.Unmarshal([]byte(c.module), &section); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		modules[name] = map[string]any{"prober": c.prober, "timeout": "5s", c.prober: section}
	}
	return yaml.Marshal(map[string]any{"modules": modules})
}

type probeResult struct {
	logs    string
	metrics map[string]*dto.MetricFamily
}

func probe(t *testing.T, module, target string) probeResult {
	t.Helper()
	return probeAt(t, exporterURL, module, target)
}

func probeAt(t *testing.T, base, module, target string) probeResult {
	t.Helper()
	q := url.Values{"module": {module}, "target": {target}, "debug": {"true"}}
	body := mustGet(t, base+"/probe?"+q.Encode())
	// The headings come from the debug output in prober/handler.go.
	logs, rest, ok := strings.Cut(body, "Metrics that would have been returned:\n")
	require.True(t, ok, "unexpected debug output:\n%s", body)
	text, _, _ := strings.Cut(rest, "\n\n\nModule configuration:")
	p := expfmt.NewTextParser(model.UTF8Validation)
	metrics, err := p.TextToMetricFamilies(strings.NewReader(text))
	require.NoError(t, err, text)
	return probeResult{logs: logs, metrics: metrics}
}

// value matches the first series whose labels include labels.
func (r probeResult) value(name string, labels map[string]string) (float64, bool) {
	mf, ok := r.metrics[name]
	if !ok {
		return 0, false
	}
	for _, m := range mf.GetMetric() {
		if hasLabels(m, labels) {
			switch {
			case m.GetGauge() != nil:
				return m.GetGauge().GetValue(), true
			case m.GetCounter() != nil:
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

func hasLabels(m *dto.Metric, want map[string]string) bool {
	got := map[string]string{}
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func wantSuccess(t *testing.T, base, module, target string, want float64) {
	t.Helper()
	r := probeAt(t, base, module, target)
	got, _ := r.value("probe_success", nil)
	require.Equal(t, want, got, "%s %s: probe_success\nlogs:\n%s", module, target, r.logs)
}

// runCases starts the exporters the cases need, with a config of only these cases, and runs each case.
func runCases(t *testing.T, cases []probeCase) {
	t.Helper()
	bases := startCaseExporters(t, cases)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := probeAt(t, bases[exporterName(c)], c.moduleName(), c.target)
			got, ok := r.value("probe_success", nil)
			require.True(t, ok, "no probe_success\nlogs:\n%s", r.logs)
			require.Equal(t, c.want, got, "probe_success\nlogs:\n%s", r.logs)
			if c.wantLog != "" {
				require.Contains(t, r.logs, c.wantLog)
			}
			for _, m := range c.metrics {
				v, ok := r.value(m.name, m.labels)
				require.True(t, ok, "%s %v is missing", m.name, m.labels)
				require.Equal(t, m.value, v, "%s %v", m.name, m.labels)
			}
		})
	}
}

// startCaseExporters writes the cases' modules to a config file and starts one exporter per exporter name the cases use.
// It returns the base URL of each exporter by name.
func startCaseExporters(t *testing.T, cases []probeCase) map[string]string {
	t.Helper()
	cfg, err := moduleConfig(cases)
	require.NoError(t, err)
	prefix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "config", prefix+".yml"), cfg, 0o644))

	bases := map[string]string{}
	argsByName := map[string][]string{}
	for _, c := range cases {
		name := exporterName(c)
		if _, ok := bases[name]; ok {
			require.True(t, slices.Equal(argsByName[name], c.dockerArgs), "%s: cases on exporter %s need the same dockerArgs", c.moduleName(), name)
			continue
		}
		argsByName[name] = c.dockerArgs
		base := "http://" + startExporter(t, prefix+"-"+name, c.dockerArgs, "--config.file=/config/"+prefix+".yml", "--log.prober=debug")
		waitStatus(t, httpClient, base+"/-/healthy", http.StatusOK)
		bases[name] = base
	}
	return bases
}

func exporterName(c probeCase) string {
	if c.exporter == "" {
		return "default"
	}
	return c.exporter
}
