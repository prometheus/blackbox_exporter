package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/blackbox_exporter/config"
)

var c = &config.Config{
	Modules: map[string]config.Module{
		"http_2xx": config.Module{
			Prober:  "http",
			Timeout: 10 * time.Second,
		},
	},
}

func TestPrometheusTimeoutHTTP(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer ts.Close()

	req, err := http.NewRequest("GET", "?target="+ts.URL+"&config={\"http\":{\"method\":\"POST\"}}", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "1")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, c)
	})

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("probe request handler returned wrong status code: %v, want %v", status, http.StatusOK)
	}
}
