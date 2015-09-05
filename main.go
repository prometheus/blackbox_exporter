package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/brian-brazil/blackbox_exporter/probers"
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
	success := probers.Probers["http"](target, w)
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
