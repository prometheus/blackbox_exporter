// Copyright 2015 The Prometheus Authors
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
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestHTTPStatusCodes(t *testing.T) {
	tests := []struct {
		StatusCode       int
		ValidStatusCodes []int
		ShouldSucceed    bool
	}{
		{200, []int{}, true},
		{201, []int{}, true},
		{299, []int{}, true},
		{300, []int{}, false},
		{404, []int{}, false},
		{404, []int{200, 404}, true},
		{200, []int{200, 404}, true},
		{201, []int{200, 404}, false},
		{404, []int{404}, true},
		{200, []int{404}, false},
	}
	for i, test := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.StatusCode)
		}))
		defer ts.Close()
		registry := prometheus.NewRegistry()
		recorder := httptest.NewRecorder()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result := ProbeHTTP(testCTX, ts.URL,
			config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{ValidStatusCodes: test.ValidStatusCodes}}, registry, log.NewNopLogger())
		body := recorder.Body.String()
		if result != test.ShouldSucceed {
			t.Fatalf("Test %d had unexpected result: %s", i, body)
		}
	}
}

func TestValidHTTPVersion(t *testing.T) {
	tests := []struct {
		ValidHTTPVersions []string
		ShouldSucceed     bool
	}{
		{[]string{}, true},
		{[]string{"HTTP/1.1"}, true},
		{[]string{"HTTP/1.1", "HTTP/2"}, true},
		{[]string{"HTTP/2"}, false},
	}
	for i, test := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		}))
		defer ts.Close()
		recorder := httptest.NewRecorder()
		registry := prometheus.NewRegistry()
		result := ProbeHTTP(context.Background(), ts.URL,
			config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
				ValidHTTPVersions: test.ValidHTTPVersions,
			}}, registry, log.NewNopLogger())
		body := recorder.Body.String()
		if result != test.ShouldSucceed {
			t.Fatalf("Test %v had unexpected result: %s", i, body)
		}
	}
}

func TestRedirectFollowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/noredirect", http.StatusFound)
		}
	}))
	defer ts.Close()

	// Follow redirect, should succeed with 200.
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Redirect test failed unexpectedly, got %s", body)
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_http_redirects": 1,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestRedirectNotFollowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/noredirect", http.StatusFound)
	}))
	defer ts.Close()

	// Follow redirect, should succeed with 200.
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{NoFollowRedirects: true, ValidStatusCodes: []int{302}}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Redirect test failed unexpectedly, got %s", body)
	}

}

func TestPost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{Method: "POST"}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Post test failed unexpectedly, got %s", body)
	}
}

func TestBasicAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: false},
				BasicAuth: &pconfig.BasicAuth{Username: "username", Password: "password"},
			},
		}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("HTTP probe failed, got %s", body)
	}
}

func TestBearerToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
			HTTPClientConfig: pconfig.HTTPClientConfig{
				BearerToken: pconfig.Secret("mysecret"),
			},
		}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("HTTP probe failed, got %s", body)
	}
}

func TestFailIfNotSSL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfNotSSL: true}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if result {
		t.Fatalf("Fail if not SSL test suceeded unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_http_ssl": 0,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestFailIfMatchesRegexp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Bad news: could not connect to database server")
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfMatchesRegexp: []string{"could not connect to database"}}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if result {
		t.Fatalf("Regexp test succeeded unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_failed_due_to_regex": 1,
	}
	checkRegistryResults(expectedResults, mfs, t)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Download the latest version here")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfMatchesRegexp: []string{"could not connect to database"}}}, registry, log.NewNopLogger())
	body = recorder.Body.String()
	if !result {
		t.Fatalf("Regexp test failed unexpectedly, got %s", body)
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults = map[string]float64{
		"probe_failed_due_to_regex": 0,
	}
	checkRegistryResults(expectedResults, mfs, t)

	// With multiple regexps configured, verify that any matching regexp causes
	// the probe to fail, but probes succeed when no regexp matches.
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "internal error")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfMatchesRegexp: []string{"could not connect to database", "internal error"}}}, registry, log.NewNopLogger())
	body = recorder.Body.String()
	if result {
		t.Fatalf("Regexp test succeeded unexpectedly, got %s", body)
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello world")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfMatchesRegexp: []string{"could not connect to database", "internal error"}}}, registry, log.NewNopLogger())
	body = recorder.Body.String()
	if !result {
		t.Fatalf("Regexp test failed unexpectedly, got %s", body)
	}
}

func TestFailIfNotMatchesRegexp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Bad news: could not connect to database server")
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfNotMatchesRegexp: []string{"Download the latest version here"}}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if result {
		t.Fatalf("Regexp test succeeded unexpectedly, got %s", body)
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Download the latest version here")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfNotMatchesRegexp: []string{"Download the latest version here"}}}, registry, log.NewNopLogger())
	body = recorder.Body.String()
	if !result {
		t.Fatalf("Regexp test failed unexpectedly, got %s", body)
	}

	// With multiple regexps configured, verify that any non-matching regexp
	// causes the probe to fail, but probes succeed when all regexps match.
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Download the latest version here")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfNotMatchesRegexp: []string{"Download the latest version here", "Copyright 2015"}}}, registry, log.NewNopLogger())
	body = recorder.Body.String()
	if result {
		t.Fatalf("Regexp test succeeded unexpectedly, got %s", body)
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Download the latest version here. Copyright 2015 Test Inc.")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{FailIfNotMatchesRegexp: []string{"Download the latest version here", "Copyright 2015"}}}, registry, log.NewNopLogger())
	body = recorder.Body.String()
	if !result {
		t.Fatalf("Regexp test failed unexpectedly, got %s", body)
	}
}

func TestHTTPHeaders(t *testing.T) {
	headers := map[string]string{
		"Host":            "my-secret-vhost.com",
		"User-Agent":      "unsuspicious user",
		"Accept-Language": "en-US",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, value := range headers {
			if strings.Title(key) == "Host" {
				if r.Host != value {
					t.Errorf("Unexpected host: expected %q, got %q.", value, r.Host)
				}
				continue
			}
			if got := r.Header.Get(key); got != value {
				t.Errorf("Unexpected value of header %q: expected %q, got %q", key, value, got)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
		Headers: headers,
	}}, registry, log.NewNopLogger())
	if !result {
		t.Fatalf("Probe failed unexpectedly.")
	}
}

func TestFailIfSelfSignedCA(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: false},
			},
		}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if result {
		t.Fatalf("Fail if selfsigned CA test suceeded unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_http_ssl": 0,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestSucceedIfSelfSignedCA(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: true},
			},
		}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Fail if (not strict) selfsigned CA test fails unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_http_ssl": 1,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestTLSConfigIsIgnoredForPlainHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: false},
			},
		}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Fail if InsecureSkipVerify affects simple http fails unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_http_ssl": 0,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestHTTPUsesTargetAsTLSServerName(t *testing.T) {
	// Create test certificates valid for 1 day.
	certExpiry := time.Now().AddDate(0, 0, 1)
	testcertPem, testKeyPem := generateTestCertificate(certExpiry, false)

	// CAFile must be passed via filesystem, use a tempfile.
	tmpCaFile, err := ioutil.TempFile("", "cafile.pem")
	if err != nil {
		t.Fatalf("Error creating CA tempfile: %s", err)
	}
	if _, err = tmpCaFile.Write(testcertPem); err != nil {
		t.Fatalf("Error writing CA tempfile: %s", err)
	}
	if err = tmpCaFile.Close(); err != nil {
		t.Fatalf("Error closing CA tempfile: %s", err)
	}
	defer os.Remove(tmpCaFile.Name())

	testcert, err := tls.X509KeyPair(testcertPem, testKeyPem)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode TLS testing keypair: %s\n", err))
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{testcert},
	}
	ts.StartTLS()
	defer ts.Close()

	registry := prometheus.NewRegistry()
	module := config.Module{
		Timeout: time.Second,
		HTTP: config.HTTPProbe{
			PreferredIPProtocol: "ip4",
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{
					CAFile: tmpCaFile.Name(),
				},
			},
		},
	}

	// Replace IP address with hostname.
	url := strings.Replace(ts.URL, "127.0.0.1", "localhost", -1)
	url = strings.Replace(url, "[::1]", "localhost", -1)

	result := ProbeHTTP(context.Background(), url, module, registry, log.NewNopLogger())
	if !result {
		t.Fatalf("TLS probe failed unexpectedly")
	}
}

func TestHTTPPhases(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	// Follow redirect, should succeed with 200.
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
		HTTPClientConfig: pconfig.HTTPClientConfig{
			TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: true},
		},
	}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("HTTP Phases test failed unexpectedly, got %s", body)
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	foundLabel := map[string]bool{
		"connect":    false,
		"processing": false,
		"resolve":    false,
		"transfer":   false,
		"tls":        false,
	}
	for _, mf := range mfs {
		if mf.GetName() == "probe_http_duration_seconds" {
			found = true
			for _, metric := range mf.GetMetric() {
				for _, lp := range metric.Label {
					if lp.GetName() == "phase" {
						f, ok := foundLabel[lp.GetValue()]
						if !ok {
							t.Fatalf("Unexpected label phase=%s", lp.GetValue())
						}
						if f {
							t.Fatalf("Label phase=%s duplicated", lp.GetValue())
						}
						foundLabel[lp.GetValue()] = true
					}
				}
			}

		}
	}
	if !found {
		t.Fatal("probe_http_duration_seconds not found")
	}
	for lv, found := range foundLabel {
		if !found {
			t.Fatalf("Label phase=%s not found", lv)
		}
	}
}

func TestCookieJar(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			expiration := time.Now().Add(365 * 24 * time.Hour)
			cookie := http.Cookie{Name: "somecookie", Value: "cookie", Expires: expiration}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/noredirect", http.StatusFound)
		}
		if r.URL.Path == "/noredirect" {
			cookie, err := r.Cookie("somecookie")
			if err != nil {
				t.Fatalf("Error retrieving cookie, got %v", err)
			}
			if cookie.String() != "somecookie=cookie" {
				t.Errorf("Error incorrect cookie value received, got %v, wanted %v", cookie.String(), "somecookie=cookie")
			}
		}
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{}}, registry, log.NewNopLogger())
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Redirect test failed unexpectedly, got %s", body)
	}
}
