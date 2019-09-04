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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

var c = &config.Config{
	Modules: map[string]config.Module{
		"http_2xx": config.Module{
			Prober:  "http",
			Timeout: 10 * time.Second,
			HTTP: config.HTTPProbe{
				HTTPClientConfig: pconfig.HTTPClientConfig{
					BearerToken: "mysecret",
				},
			},
		},
	},
}

func TestPrometheusTimeoutHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer ts.Close()

	req, err := http.NewRequest("GET", "?target="+ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "1")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, c, log.NewNopLogger(), &resultHistory{})
	})

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("probe request handler returned wrong status code: %v, want %v", status, http.StatusOK)
	}
}

func TestPrometheusConfigSecretsHidden(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer ts.Close()

	req, err := http.NewRequest("GET", "?debug=true&target="+ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, c, log.NewNopLogger(), &resultHistory{})
	})
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "mysecret") {
		t.Errorf("Secret exposed in debug config output: %v", body)
	}
	if !strings.Contains(body, "<secret>") {
		t.Errorf("Hidden secret missing from debug config output: %v", body)
	}
}

func TestDebugOutputSecretsHidden(t *testing.T) {
	module := c.Modules["http_2xx"]
	out := DebugOutput(&module, &bytes.Buffer{}, prometheus.NewRegistry())

	if strings.Contains(out, "mysecret") {
		t.Errorf("Secret exposed in debug output: %v", out)
	}
	if !strings.Contains(out, "<secret>") {
		t.Errorf("Hidden secret missing from debug output: %v", out)
	}
}

func TestTimeoutIsSetCorrectly(t *testing.T) {
	var tests = []struct {
		inModuleTimeout     time.Duration
		inPrometheusTimeout string
		inOffset            float64
		outTimeout          float64
	}{
		{0 * time.Second, "15", 0.5, 14.5},
		{0 * time.Second, "15", 0, 15},
		{20 * time.Second, "15", 0.5, 14.5},
		{20 * time.Second, "15", 0, 15},
		{5 * time.Second, "15", 0, 5},
		{5 * time.Second, "15", 0.5, 5},
		{10 * time.Second, "", 0.5, 10},
		{10 * time.Second, "10", 0.5, 9.5},
		{9500 * time.Millisecond, "", 0.5, 9.5},
		{9500 * time.Millisecond, "", 1, 9.5},
		{0 * time.Second, "", 0.5, 119.5},
		{0 * time.Second, "", 0, 120},
	}

	for _, v := range tests {
		request, _ := http.NewRequest("GET", "", nil)
		request.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", v.inPrometheusTimeout)
		module := config.Module{
			Timeout: v.inModuleTimeout,
		}

		timeout, _ := getTimeout(request, module, v.inOffset)
		if timeout != v.outTimeout {
			t.Errorf("timeout is incorrect: %v, want %v", timeout, v.outTimeout)
		}
	}
}

func TestExternalURL(t *testing.T) {
	hostname := "foo"
	for _, tc := range []struct {
		hostnameResolver func() (string, error)
		external         string
		listen           string

		expURL string
		err    bool
	}{
		{
			listen: ":9093",
			expURL: "http://" + hostname + ":9093",
		},
		{
			listen: "localhost:9093",
			expURL: "http://" + hostname + ":9093",
		},
		{
			listen: "localhost:",
			expURL: "http://" + hostname + ":",
		},
		{
			external: "https://host.example.com",
			expURL:   "https://host.example.com",
		},
		{
			external: "https://host.example.com/",
			expURL:   "https://host.example.com",
		},
		{
			external: "http://host.example.com/alertmanager",
			expURL:   "http://host.example.com/alertmanager",
		},
		{
			external: "http://host.example.com/alertmanager/",
			expURL:   "http://host.example.com/alertmanager",
		},
		{
			external: "http://host.example.com/////alertmanager//",
			expURL:   "http://host.example.com/////alertmanager",
		},
		{
			err: true,
		},
		{
			hostnameResolver: func() (string, error) { return "", fmt.Errorf("some error") },
			err:              true,
		},
		{
			external: "://broken url string",
			err:      true,
		},
		{
			external: "host.example.com:8080",
			err:      true,
		},
	} {
		tc := tc
		if tc.hostnameResolver == nil {
			tc.hostnameResolver = func() (string, error) {
				return hostname, nil
			}
		}
		t.Run(fmt.Sprintf("external=%q,listen=%q", tc.external, tc.listen), func(t *testing.T) {
			u, err := extURL(log.NewNopLogger(), tc.hostnameResolver, tc.listen, tc.external)
			if tc.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expURL, u.String())
		})
	}
}
