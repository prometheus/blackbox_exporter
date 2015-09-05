package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var addr = flag.String("web.listen-address", ":8080", "The address to listen on for HTTP requests.")

type Config struct {
  Modules map[string]Module `yaml:"modules"`
}

type Module struct {
  Prober string  `yaml:"prober"`
  Timeout time.Duration `yaml:"timeout"`
  Config interface{} `yaml:"config"`
}

type HTTPProbe struct {
  // Defaults to 2xx.
  ValidStatusCodes []int `yaml:"valid_status_codes"`
  FollowRedirects bool `yaml:"follow_redirects"`
  FailIfSSL bool `yaml:"fail_if_ssl"`
  FailIfNotSSL bool `yaml:"fail_if_not_ssl"`
}

func probeHTTP(target string, w http.ResponseWriter) (success bool) {
	var isSSL int
	resp, err := http.Get(target)
	if err == nil {
		if 200 >= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		}
		defer resp.Body.Close()
	}
	if resp.TLS != nil {
		isSSL = 1
	}
	fmt.Fprintf(w, "probe_http_status_code %d\n", resp.StatusCode)
	fmt.Fprintf(w, "probe_http_content_length %d\n", resp.ContentLength)
	fmt.Fprintf(w, "probe_http_ssl %d\n", isSSL)
	return
}

func probeHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	target := params.Get("target")
	module := params.Get("module")
	if target == "" {
		http.Error(w, "Target parameter is missing", 400)
		return
	}
	if module == "" {
		module = "http2xx"
	}
	start := time.Now()
	success := probeHTTP(target, w)
	fmt.Fprintf(w, "probe_duration_seconds %f\n", float64(time.Now().Sub(start))/1e9)
	if success {
		fmt.Fprintf(w, "probe_success %d\n", 1)
	} else {
		fmt.Fprintf(w, "probe_success %d\n", 0)
	}
}

func main() {
	flag.Parse()
	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc("/probe", probeHandler)
	http.ListenAndServe(*addr, nil)
}
