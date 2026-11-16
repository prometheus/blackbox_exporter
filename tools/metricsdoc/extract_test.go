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

package main

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeTree writes files, keyed by slash-separated path, under a temporary
// directory and returns the directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestExtract(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.go": `package main

import (
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var unknown = promauto.NewCounter(prometheus.CounterOpts{
	Name: "demo_unknown_total",
	Help: "Unknown | modules.",
})

func init() {
	prometheus.MustRegister(versioncollector.NewCollector("demo"))
}
`,
		"config/config.go": `package config

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func New(reg prometheus.Registerer) {
	promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Namespace: "demo",
		Subsystem: "config",
		Name:      "loaded",
		Help:      "Config " + "loaded.",
	})
}
`,
		"prober/handler.go": `package prober

import prom "github.com/prometheus/client_golang/prometheus"

var Probers = map[string]ProbeFn{
	"b": ProbeB,
	"a": ProbeA,
}

func Handler() {
	prom.NewGauge(prom.GaugeOpts{Name: "probe_success", Help: "Success."})
}
`,
		"prober/probers.go": `package prober

import "github.com/prometheus/client_golang/prometheus"

const helpShared = "Shared."

var sharedOpts = prometheus.GaugeOpts{Name: "probe_shared", Help: helpShared}

func ProbeA() bool {
	prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_a_duration_seconds", Help: "A."}, []string{"phase"})
	shared()
	// A local variable, a field name and a field, none of them the function onlyB.
	onlyB := opts{onlyB: true}.onlyB
	return onlyB
}

func ProbeB() bool {
	labels := []string{"x", "y"}
	if true {
		labels := []string{"inner"} // Another variable, in an inner block.
		_ = labels
	}
	prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "probe_b_seconds", Help: helpB}, labels)
	run(shared)
	expectInfo(nil)
	return true
}

func shared() {
	prometheus.NewGauge(sharedOpts)
}

func expectInfo(names []string) {
	prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_expect_info", Help: "Matched."}, names)
	onlyB()
}

func run(f func()) { f() }

type opts struct{ onlyB bool }

func onlyB() {
	prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_only_b", Help: "Only B."})
}
`,
		// Only the files built for linux/amd64 are read.
		"prober/help_linux.go": "package prober\n\nconst helpB = \"B.\"\n",
		"prober/help_other.go": "//go:build !linux\n\npackage prober\n\nconst helpB = \"B elsewhere.\"\n",
		// Test files and testdata are not read.
		"prober/probers_test.go": `package prober

import "github.com/prometheus/client_golang/prometheus"

var _ = prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_test_only", Help: "Test."})
`,
		"prober/testdata/x.go": `package x

import "github.com/prometheus/client_golang/prometheus"

var _ = prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_testdata_only", Help: "Test."})
`,
	})

	c, err := extract(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"b", "a"}; !reflect.DeepEqual(c.Probers, want) {
		t.Errorf("probers: got %v, want %v", c.Probers, want)
	}
	want := []metric{
		{Name: "demo_build_info", Type: "gauge", Help: "A metric with a constant '1' value labeled by version, revision, branch, goversion from which demo was built, and the goos and goarch for the build.", Labels: []string{"version", "revision", "branch", "goversion", "goos", "goarch", "tags"}, Exporter: true},
		{Name: "demo_config_loaded", Type: "gauge", Help: "Config loaded.", Exporter: true},
		{Name: "demo_unknown_total", Type: "counter", Help: "Unknown | modules.", Exporter: true},
		{Name: "probe_a_duration_seconds", Type: "gauge", Help: "A.", Labels: []string{"phase"}, Probers: []string{"a"}},
		{Name: "probe_b_seconds", Type: "histogram", Help: "B.", Labels: []string{"x", "y"}, Probers: []string{"b"}},
		{Name: "probe_expect_info", Type: "gauge", Help: "Matched.", LabelsFrom: "query_response[].labels", Probers: []string{"b"}},
		{Name: "probe_only_b", Type: "gauge", Help: "Only B.", Probers: []string{"b"}},
		{Name: "probe_shared", Type: "gauge", Help: "Shared.", Probers: []string{"b", "a"}},
		{Name: "probe_success", Type: "gauge", Help: "Success.", EveryProbe: true},
	}
	var got []metric
	for _, m := range c.Metrics {
		mc := *m
		mc.Sites = nil
		got = append(got, mc)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("metrics:\ngot  %+v\nwant %+v", got, want)
	}
	for _, m := range c.Metrics {
		if m.Name == "probe_shared" {
			if want := []site{{Pos: "prober/probers.go:30", Func: "shared"}}; !reflect.DeepEqual(m.Sites, want) {
				t.Errorf("probe_shared sites: got %+v, want %+v", m.Sites, want)
			}
		}
	}
}

func TestExtractErrors(t *testing.T) {
	const header = "package prober\n\nimport \"github.com/prometheus/client_golang/prometheus\"\n\n"
	handler := header + "var Probers = map[string]ProbeFn{\"a\": ProbeA}\n\nfunc ProbeA() bool { return helper() }\n"

	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name: "non-constant name",
			files: map[string]string{"prober/p.go": header + `func helper() bool {
	name := strings.ToLower("X")
	prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: "h"})
	return true
}
`},
			want: "prober/p.go:7: Name is not a constant string",
		},
		{
			name: "options not a literal",
			files: map[string]string{"prober/p.go": header + `func helper() bool {
	prometheus.NewGauge(opts())
	return true
}
`},
			want: "prober/p.go:6: cannot resolve the options of NewGauge",
		},
		{
			name: "duplicate with different help",
			files: map[string]string{"prober/p.go": header + `func helper() bool {
	prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_x", Help: "one"})
	prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_x", Help: "two"})
	return true
}
`},
			want: "prober/p.go:7: metric probe_x is also defined at prober/p.go:6",
		},
		{
			name: "unreachable from probers",
			files: map[string]string{"prober/p.go": header + `func helper() bool { return true }

func unused() {
	prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_x", Help: "h"})
}
`},
			want: "prober/p.go:8: metric probe_x is not reachable from any prober",
		},
		{
			name: "computed label names",
			files: map[string]string{"prober/p.go": header + `func helper() bool {
	prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_x", Help: "h"}, labelNames())
	return true
}
`},
			want: "prober/p.go:6: label names of probe_x are not a constant []string",
		},
		{
			name: "unsupported constructor",
			files: map[string]string{"prober/p.go": header + `func helper() bool {
	prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "probe_x", Help: "h"}, func() float64 { return 1 })
	return true
}
`},
			want: "prober/p.go:6: NewGaugeFunc is not supported",
		},
		{
			name: "unknown constructor receiver",
			files: map[string]string{"prober/p.go": header + `func helper() bool {
	factory.NewGauge(prometheus.GaugeOpts{Name: "probe_x", Help: "h"})
	return true
}
`},
			want: "prober/p.go:6: NewGauge is called on something other than the prometheus or promauto package",
		},
		{
			name: "const labels",
			files: map[string]string{"prober/p.go": header + `func helper() bool {
	prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_x", Help: "h", ConstLabels: prometheus.Labels{"a": "b"}})
	return true
}
`},
			want: "prober/p.go:6: ConstLabels are not supported",
		},
		{
			name: "unknown package",
			files: map[string]string{
				"prober/p.go":     header + "func helper() bool { return true }\n",
				"internal/x/x.go": "package x\n\nimport \"github.com/prometheus/client_golang/prometheus\"\n\nvar g = prometheus.NewGauge(prometheus.GaugeOpts{Name: \"x\", Help: \"h\"})\n",
			},
			want: `internal/x/x.go:5: metric x is defined in package directory "internal/x"`,
		},
		{
			name: "parameter that hides a constant",
			files: map[string]string{"prober/p.go": header + `const help = "Package help."

func helper() bool {
	gauge("Real help.")
	return true
}

func gauge(help string) {
	prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_x", Help: help})
}
`},
			want: "prober/p.go:13: Help is not a constant string",
		},
		{
			name: "range variable that hides a variable",
			files: map[string]string{"prober/p.go": header + `var labels = []string{"static"}

func helper() bool {
	for _, labels := range [][]string{{"real"}} {
		prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_x", Help: "h"}, labels)
	}
	return true
}
`},
			want: "prober/p.go:9: label names of probe_x are not a constant []string",
		},
		{
			name: "options changed after their declaration",
			files: map[string]string{"prober/p.go": header + `var baseOpts = prometheus.GaugeOpts{Name: "probe_base", Help: "Base."}

func helper() bool {
	opts := baseOpts
	opts.Name = "probe_x"
	prometheus.NewGauge(opts)
	return true
}
`},
			want: "prober/p.go:10: cannot resolve the options of NewGauge",
		},
		{
			name: "metric reached through a method",
			files: map[string]string{"prober/p.go": header + `type t struct{}

func (t) run() { shared() }

func helper() bool {
	t{}.run()
	shared()
	return true
}

func shared() { prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_x", Help: "h"}) }
`},
			want: "prober/p.go:7: t.run leads to shared, which defines probe_x",
		},
		{
			name: "metric reached through a package-level variable",
			files: map[string]string{"prober/p.go": header + `var steps = []func(){shared}

func helper() bool {
	for _, step := range steps {
		step()
	}
	return true
}

func shared() { prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_x", Help: "h"}) }
`},
			want: "prober/p.go:5: var steps leads to shared, which defines probe_x",
		},
		{
			name: "metric in a file not built for linux",
			files: map[string]string{
				"prober/p.go": header + "func helper() bool { return true }\n",
				"gen.go":      "//go:build ignore\n\npackage main\n\nimport \"github.com/prometheus/client_golang/prometheus\"\n\nvar g = prometheus.NewGauge(prometheus.GaugeOpts{Name: \"x\", Help: \"h\"})\n",
			},
			want: "gen.go:7: metric defined in a file that is not built for linux/amd64",
		},
		{
			name:  "no probers map",
			files: map[string]string{"prober/handler.go": header + "func Handler() {}\n"},
			want:  "prober: found 0 map[string]ProbeFn literals, want exactly 1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"prober/handler.go": handler}
			maps.Copy(files, tc.files)
			_, err := extract(writeTree(t, files))
			if err == nil {
				t.Fatalf("got no error, want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got error %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
