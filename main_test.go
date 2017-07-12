package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var c = &Config{
	Modules: map[string]Module{
		"http_2xx": Module{
			Prober:  "http",
			Timeout: 10 * time.Second,
		},
	},
}

func TestPrometheusTimeout(t *testing.T) {

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
		probeHandler(w, r, c)
	})

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("probe request handler returned wrong status code: %v, want %v", status, http.StatusOK)
	}
}
