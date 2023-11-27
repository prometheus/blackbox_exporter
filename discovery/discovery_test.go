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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-kit/log"

	"github.com/prometheus/blackbox_exporter/config"
)

var c = &config.Config{
	Modules: map[string]config.Module{
		"http_2xx": {
			Prober:  "http",
			Timeout: 10 * time.Second,
			HTTP:    config.HTTPProbe{},
		},
	},
	Discoveries: config.Discoveries{
		Configs: []*config.Discovery{
			&config.Discovery{
				Hostname: str("hostname"),
				Module:   "http_2xx",
				Targets: []string{
					"http://www.google.com",
				},
			},
			&config.Discovery{
				Module: "non-existing-module",
				Targets: []string{
					"http://www.google.com",
				},
			},
		},
	},
}

func str(s string) *string {
	return &s
}

func TestDiscoveryConfigs(t *testing.T) {
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler(w, r, "/", c, log.NewNopLogger())
	})

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("discovery request handler returned wrong status code: %v, want %v", status, http.StatusOK)
	}
	if body := rr.Body.String(); string(body) != `[{"targets": ["localhost:9115"],"labels":{"__scheme__":"http","__metrics_path__":"/probe","__param_module":"http_2xx","__param_target":"http://www.google.com",__param_hostname":"hostname"}}]` {
		t.Errorf("discovery returns unexpected body:\n%v\ninsted of:\n"+`[{"targets": ["localhost:9115"],"labels":{"__scheme__":"http","__metrics_path__":"/probe","__param_module":"http_2xx","__param_target":"http://www.google.com",__param_hostname":"hostname"}}]`, body)
	}
}
