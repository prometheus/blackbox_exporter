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
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
)

var (
	configFile    = flag.String("config.file", "blackbox.yml", "Blackbox exporter configuration file.")
	listenAddress = flag.String("web.listen-address", ":9115", "The address to listen on for HTTP requests.")
	showVersion   = flag.Bool("version", false, "Print version information.")
)

type Config struct {
	Modules map[string]Module `yaml:"modules"`
}

type Module struct {
	Prober  string        `yaml:"prober"`
	Timeout time.Duration `yaml:"timeout"`
	HTTP    HTTPProbe     `yaml:"http"`
	TCP     TCPProbe      `yaml:"tcp"`
	ICMP    ICMPProbe     `yaml:"icmp"`
	DNS     DNSProbe      `yaml:"dns"`
}

type ResponseHeader struct {
	Required               bool     `yaml:"required"`
	FailIfMatchesRegexp    []string `yaml:"fail_if_matches_regexp"`
	FailIfNotMatchesRegexp []string `yaml:"fail_if_not_matches_regexp"`
}

type HTTPProbe struct {
	// Defaults to 2xx.
	ValidStatusCodes       []int                     `yaml:"valid_status_codes"`
	NoFollowRedirects      bool                      `yaml:"no_follow_redirects"`
	FailIfSSL              bool                      `yaml:"fail_if_ssl"`
	FailIfNotSSL           bool                      `yaml:"fail_if_not_ssl"`
	Method                 string                    `yaml:"method"`
	Headers                map[string]string         `yaml:"headers"`
	FailIfMatchesRegexp    []string                  `yaml:"fail_if_matches_regexp"`
	FailIfNotMatchesRegexp []string                  `yaml:"fail_if_not_matches_regexp"`
	ResponseHeaders        map[string]ResponseHeader `yaml:"response_headers"`
}

type QueryResponse struct {
	Expect string `yaml:"expect"`
	Send   string `yaml:"send"`
}

type TCPProbe struct {
	QueryResponse []QueryResponse  `yaml:"query_response"`
	TLS           bool             `yaml:"tls"`
	TLSConfig     config.TLSConfig `yaml:"tls_config"`
}

type ICMPProbe struct {
}

type DNSProbe struct {
	Protocol           string         `yaml:"protocol"` // Defaults to "udp".
	QueryName          string         `yaml:"query_name"`
	QueryType          string         `yaml:"query_type"`   // Defaults to ANY.
	ValidRcodes        []string       `yaml:"valid_rcodes"` // Defaults to NOERROR.
	ValidateAnswer     DNSRRValidator `yaml:"validate_answer_rrs"`
	ValidateAuthority  DNSRRValidator `yaml:"validate_authority_rrs"`
	ValidateAdditional DNSRRValidator `yaml:"validate_additional_rrs"`
}

type DNSRRValidator struct {
	FailIfMatchesRegexp    []string `yaml:"fail_if_matches_regexp"`
	FailIfNotMatchesRegexp []string `yaml:"fail_if_not_matches_regexp"`
}

var Probers = map[string]func(string, http.ResponseWriter, Module) bool{
	"http": probeHTTP,
	"tcp":  probeTCP,
	"icmp": probeICMP,
	"dns":  probeDNS,
}

func probeHandler(w http.ResponseWriter, r *http.Request, config *Config) {
	params := r.URL.Query()
	target := params.Get("target")
	moduleName := params.Get("module")
	if target == "" {
		http.Error(w, "Target parameter is missing", 400)
		return
	}
	if moduleName == "" {
		moduleName = "http_2xx"
	}
	module, ok := config.Modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unkown module %s", moduleName), 400)
		return
	}
	prober, ok := Probers[module.Prober]
	if !ok {
		http.Error(w, fmt.Sprintf("Unkown prober %s", module.Prober), 400)
		return
	}
	start := time.Now()
	success := prober(target, w, module)
	fmt.Fprintf(w, "probe_duration_seconds %f\n", float64(time.Now().Sub(start))/1e9)
	if success {
		fmt.Fprintf(w, "probe_success %d\n", 1)
	} else {
		fmt.Fprintf(w, "probe_success %d\n", 0)
	}
}

func init() {
	prometheus.MustRegister(version.NewCollector("blackbox_exporter"))
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Print("blackbox_exporter"))
		os.Exit(0)
	}

	log.Infoln("Starting blackbox_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	yamlFile, err := ioutil.ReadFile(*configFile)

	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	config := Config{}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %s", err)
	}

	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc("/probe",
		func(w http.ResponseWriter, r *http.Request) {
			probeHandler(w, r, &config)
		})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head><title>Blackbox Exporter</title></head>
            <body>
            <h1>Blackbox Exporter</h1>
            <p><a href="/probe?target=prometheus.io&module=http_2xx">Probe prometheus.io for http_2xx</a></p>
            <p><a href="/metrics">Metrics</a></p>
            </body>
            </html>`))
	})

	log.Infoln("Listening on", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Fatalf("Error starting HTTP server: %s", err)
	}
}
