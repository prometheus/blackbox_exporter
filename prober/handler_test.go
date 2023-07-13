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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
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
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil)
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
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil)
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
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil)
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
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil)
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
		Handler(w, r, c, log.NewNopLogger(), &ResultHistory{}, 0.5, nil, nil)
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

func TestDynamicProbe(t *testing.T) {
	const skipTlsVerifyParam = `&http.http_client_config={"tls_config":{"insecure_skip_verify":true}}`

	mockHTTPServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "value")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, r.Method+": Hello World")
	}))
	defer mockHTTPServer.Close()

	mockHTTPSServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "value")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, r.Method+": Hello World")
	}))
	defer mockHTTPSServer.Close()

	tests := []struct {
		name        string
		prober      string
		target      string
		queryParams string
		error       string
		expectBody  []string
	}{
		{
			name:        "http default",
			prober:      "http",
			target:      mockHTTPServer.URL,
			queryParams: ``,
			error:       "",
			expectBody:  []string{"probe_success 1"},
		},
		{
			name:        "http.valid_http_versions",
			prober:      "http",
			target:      mockHTTPSServer.URL,
			queryParams: `http.valid_http_versions[]=HTTP/2` + skipTlsVerifyParam,
			error:       "",
			expectBody:  []string{"HTTP/2", "probe_http_version 1.1", "probe_success 0"},
		},
		{
			name:        "http.preferred_ip_protocol",
			prober:      "http",
			target:      mockHTTPSServer.URL,
			queryParams: `http.preferred_ip_protocol=6&http.ip_protocol_fallback=false` + skipTlsVerifyParam,
			error:       "",
			expectBody:  []string{`preferred_ip_protocol: "6"`, "probe_ip_protocol 4", "probe_success 1"},
		},
		{
			name:        "http.valid_http_versions",
			prober:      "http",
			target:      mockHTTPSServer.URL,
			queryParams: `http.valid_http_versions[]=204` + skipTlsVerifyParam,
			error:       "",
			expectBody:  []string{"204", "probe_success 0"},
		},
		{
			name:        "http.fail_if_body_matches_regexp",
			prober:      "http",
			target:      mockHTTPServer.URL,
			queryParams: `http.fail_if_body_matches_regexp[]=He\S.*`,
			error:       "",
			expectBody:  []string{"fail_if_body_matches_regexp", `- He\S.*`, "probe_failed_due_to_regex 1", "probe_success 0"},
		},
		{
			name:        "http.fail_if_body_not_matches_regexp",
			prober:      "http",
			target:      mockHTTPServer.URL,
			queryParams: `http.fail_if_body_not_matches_regexp[]=\d%2B`,
			error:       "",
			expectBody:  []string{"fail_if_body_not_matches_regexp:", `- \d+`, "probe_failed_due_to_regex 1", "probe_success 0"},
		},
		{
			name:        "http.method",
			prober:      "http",
			target:      mockHTTPServer.URL,
			queryParams: `http.method=POST&http.fail_if_body_not_matches_regexp[]=POST:`,
			error:       "",
			expectBody:  []string{"method: POST", "probe_failed_due_to_regex 0", "probe_success 1"},
		},
		{
			name:        "http.fail_if_ssl",
			prober:      "http",
			target:      mockHTTPSServer.URL + skipTlsVerifyParam,
			queryParams: `http.fail_if_ssl=true`,
			error:       "",
			expectBody:  []string{"fail_if_ssl: true", "probe_success 0"},
		},
		{
			name:        "http.fail_if_not_ssl",
			prober:      "http",
			target:      mockHTTPServer.URL,
			queryParams: `http.fail_if_not_ssl=true`,
			error:       "",
			expectBody:  []string{"fail_if_not_ssl: true", "probe_success 0"},
		},
		{
			name:        "http.fail_if_header_matches",
			prober:      "http",
			target:      mockHTTPServer.URL,
			queryParams: `http.fail_if_header_matches[]={"header":"X-Custom-Header","regexp":"value"}`,
			error:       "",
			expectBody:  []string{"fail_if_header_matches", "- header: X-Custom-Header", "probe_failed_due_to_regex 1", "probe_success 0"},
		},
		{
			name:        "http.fail_if_header_not_matches",
			prober:      "http",
			target:      mockHTTPServer.URL,
			queryParams: `http.fail_if_header_not_matches[]={"header":"X-Custom-Header","regexp":"value"}`,
			error:       "",
			expectBody:  []string{"fail_if_header_not_matches", "- header: X-Custom-Header", "probe_success 1"},
		},
		{
			name:        "tcp default",
			prober:      "tcp",
			target:      mockHTTPSServer.Listener.Addr().String(),
			queryParams: ``,
			error:       "",
			expectBody:  []string{"probe_success 1"},
		},
		{
			name:        "tcp.tls",
			prober:      "tcp",
			target:      mockHTTPSServer.Listener.Addr().String(),
			queryParams: `tcp.tls=true&tcp.tls_config={"insecure_skip_verify":true}`,
			error:       "",
			expectBody:  []string{"tls: true", "probe_success 1"},
		},
		{
			name:        "dns.query_name",
			prober:      "dns",
			target:      `8.8.8.8:53`,
			queryParams: ``,
			error:       "query name must be set for DNS module",
			expectBody:  []string{},
		},
		{
			name:        "dns.query_name",
			prober:      "dns",
			target:      `8.8.8.8:53`,
			queryParams: `dns.query_name=.&dns.query_type=SOA`,
			error:       "",
			expectBody:  []string{"query_type: SOA", "probe_success 1"},
		},
		{
			name:        "dns.recursion_desired",
			prober:      "dns",
			target:      `8.8.8.8:53`,
			queryParams: `dns.recursion_desired=true&dns.query_name=.&dns.query_type=SOA`,
			error:       "",
			expectBody:  []string{"recursion_desired: true", "probe_success 1"},
		},
		{
			name:        "dns.valid_rcodes",
			prober:      "dns",
			target:      `8.8.8.8:53`,
			queryParams: `dns.valid_rcodes[]=NOERROR&dns.query_name=.&dns.query_type=SOA`,
			error:       "",
			expectBody:  []string{"valid_rcodes:", "NOERROR", "probe_success 1"},
		},
		{
			name:        "dns.validate_answer_rrs",
			prober:      "dns",
			target:      `8.8.8.8:53`,
			queryParams: `dns.validate_answer_rrs={"fail_if_matches_regexp":[".*"]}&dns.query_name=.&dns.query_type=SOA`,
			error:       "",
			expectBody:  []string{"validate_answer_rrs:", "fail_if_matches_regexp", ".*", "Answer RRs validation failed", "probe_success 0"},
		},
		{
			name:        "icmp.ttl",
			prober:      "icmp",
			target:      `127.0.0.1`,
			queryParams: `icmp.ttl=300`,
			error:       `"ttl" cannot exceed 255`,
			expectBody:  []string{"validate_answer_rrs:", "fail_if_matches_regexp", ".*", "Answer RRs validation failed", "probe_success 0"},
		},
	}

	config.InitializeBinding()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		DynamicHandler(w, r, log.NewNopLogger(), &ResultHistory{MaxResults: 0}, 0.5, nil, nil)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probeUrl := fmt.Sprintf("%s/probe/custom?prober=%s&target=%s&debug=true&%s", server.URL, tc.prober, tc.target, tc.queryParams)

			resp, err := http.Get(probeUrl)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}

			body := string(bodyBytes)

			if tc.error != "" {
				if !strings.Contains(body, tc.error) {
					t.Errorf("expected error %s not found in anser:\n%s", tc.error, body)
				}
			} else {
				if resp.StatusCode != 200 {
					t.Errorf("unexpected http status %d", resp.StatusCode)
				}

				for _, expectMetric := range tc.expectBody {
					if !strings.Contains(body, expectMetric) {
						t.Errorf("expected metric %s not found in anser:\n%s", expectMetric, body)
					}
				}
			}
		})
	}
}
