package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
