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

package prober

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

var c = &config.Config{
	Modules: map[string]config.Module{
		"http_2xx": {
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
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil, level.AllowNone())
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
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil, level.AllowNone())
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

func TestHostnameParam(t *testing.T) {
	headers := map[string]string{}
	c := &config.Config{
		Modules: map[string]config.Module{
			"http_2xx": {
				Prober:  "http",
				Timeout: 10 * time.Second,
				HTTP: config.HTTPProbe{
					Headers:            headers,
					IPProtocolFallback: true,
				},
			},
		},
	}

	// check that 'hostname' parameter make its way to Host header
	hostname := "foo.example.com"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != hostname {
			t.Errorf("Unexpected Host: expected %q, got %q.", hostname, r.Host)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	requrl := fmt.Sprintf("?debug=true&hostname=%s&target=%s", hostname, ts.URL)

	req, err := http.NewRequest("GET", requrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil, level.AllowNone())
	})

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("probe request handler returned wrong status code: %v, want %v", status, http.StatusOK)
	}

	// check that ts got the request to perform header check
	if !strings.Contains(rr.Body.String(), "probe_success 1") {
		t.Errorf("probe failed, response body: %v", rr.Body.String())
	}

	// check that host header both in config and in parameter will result in 400
	c.Modules["http_2xx"].HTTP.Headers["Host"] = hostname + ".something"

	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil, level.AllowNone())
	})

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("probe request handler returned wrong status code: %v, want %v", status, http.StatusBadRequest)
	}
}

func TestTCPHostnameParam(t *testing.T) {
	c := &config.Config{
		Modules: map[string]config.Module{
			"tls_connect": {
				Prober:  "tcp",
				Timeout: 10 * time.Second,
				TCP: config.TCPProbe{
					TLS:        true,
					IPProtocol: "ip4",
					TLSConfig:  pconfig.TLSConfig{InsecureSkipVerify: true},
				},
			},
		},
	}

	// check that 'hostname' parameter make its way to server_name in the tls_config
	hostname := "foo.example.com"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != hostname {
			t.Errorf("Unexpected Host: expected %q, got %q.", hostname, r.Host)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	requrl := fmt.Sprintf("?module=tls_connect&debug=true&hostname=%s&target=%s", hostname, ts.Listener.Addr().(*net.TCPAddr).IP.String()+":"+strconv.Itoa(ts.Listener.Addr().(*net.TCPAddr).Port))

	req, err := http.NewRequest("GET", requrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil, level.AllowNone())
	})

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("probe request handler returned wrong status code: %v, want %v", status, http.StatusOK)
	}

	// check debug output to confirm the server_name is set in tls_config and matches supplied hostname
	if !strings.Contains(rr.Body.String(), "server_name: "+hostname) {
		t.Errorf("probe failed, response body: %v", rr.Body.String())
	}

}

func TestDNSHostnameParam(t *testing.T) {
	c := &config.Config{
		Modules: map[string]config.Module{
			"dns_query_name": {
				Prober: "dns",
				DNS: config.DNSProbe{
					IPProtocol: "ip4",
					QueryName:  "foo.example.com",
				},
			},
		},
	}
	hostname := "bar.example.com"
	server, addr := startDNSServer("udp", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		answers := []string{
			fmt.Sprintf("%s 3600 IN A 127.0.0.1", hostname),
			fmt.Sprintf("%s 3600 IN A 127.0.0.2", hostname),
		}
		for _, rr := range answers {
			a, err := dns.NewRR(rr)
			if err != nil {
				panic(err)
			}
			m.Answer = append(m.Answer, a)
		}
		if err := w.WriteMsg(m); err != nil {
			panic(err)
		}
	})
	defer server.Shutdown()
	requrl := fmt.Sprintf("?module=dns_query_name&debug=true&hostname=%s&target=%s", hostname, addr)
	req, err := http.NewRequest("GET", requrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil, level.AllowNone())
	})
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("probe request handler returned wrong status code: %v, want %v", status, http.StatusOK)
	}

	// check debug output to confirm the query name is set in dns query and matches supplied hostname
	if !strings.Contains(rr.Body.String(), fmt.Sprintf("dial_protocol=%s query=%s type=255 class=1", "udp4", hostname)) {
		t.Errorf("probe failed, response body: %v", rr.Body.String())
	}
}
