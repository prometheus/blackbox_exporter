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

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/expfmt"
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
		result := probeHTTP(ts.URL, recorder,
			Module{Timeout: time.Second, HTTP: HTTPProbe{ValidStatusCodes: test.ValidStatusCodes}}, registry)
		body := recorder.Body.String()
		if result != test.ShouldSucceed {
			t.Fatalf("Test %d had unexpected result: %s", i, body)
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
	result := probeHTTP(ts.URL, recorder, Module{Timeout: time.Second, HTTP: HTTPProbe{}}, registry)
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Redirect test failed unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re := regexp.MustCompile("probe_http_redirects 1")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected one redirect, got %s", body)
	}

}

func TestRedirectNotFollowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/noredirect", http.StatusFound)
	}))
	defer ts.Close()

	// Follow redirect, should succeed with 200.
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	result := probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{NoFollowRedirects: true, ValidStatusCodes: []int{302}}}, registry)
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
	result := probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{Method: "POST"}}, registry)
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Post test failed unexpectedly, got %s", body)
	}
}

func TestFailIfNotSSL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	result := probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfNotSSL: true}}, registry)
	body := recorder.Body.String()
	if result {
		t.Fatalf("Fail if not SSL test suceeded unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re := regexp.MustCompile("probe_http_ssl 0")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected HTTP without SSL, got %s", body)
	}

}

func TestFailIfMatchesRegexp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Bad news: could not connect to database server")
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	result := probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfMatchesRegexp: []string{"could not connect to database"}}}, registry)
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
	result = probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfMatchesRegexp: []string{"could not connect to database"}}}, registry)
	body = recorder.Body.String()
	if !result {
		t.Fatalf("Regexp test failed unexpectedly, got %s", body)
	}

	// With multiple regexps configured, verify that any matching regexp causes
	// the probe to fail, but probes succeed when no regexp matches.
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "internal error")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfMatchesRegexp: []string{"could not connect to database", "internal error"}}}, registry)
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
	result = probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfMatchesRegexp: []string{"could not connect to database", "internal error"}}}, registry)
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
	result := probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfNotMatchesRegexp: []string{"Download the latest version here"}}}, registry)
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
	result = probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfNotMatchesRegexp: []string{"Download the latest version here"}}}, registry)
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
	result = probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfNotMatchesRegexp: []string{"Download the latest version here", "Copyright 2015"}}}, registry)
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
	result = probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{FailIfNotMatchesRegexp: []string{"Download the latest version here", "Copyright 2015"}}}, registry)
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
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	result := probeHTTP(ts.URL, recorder, Module{Timeout: time.Second, HTTP: HTTPProbe{
		Headers: headers,
	}}, registry)
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
	result := probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{
			TLSConfig: config.TLSConfig{InsecureSkipVerify: false},
		}}, registry)
	body := recorder.Body.String()
	if result {
		t.Fatalf("Fail if selfsigned CA test suceeded unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re := regexp.MustCompile("probe_http_ssl 0")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected HTTP without SSL because of CA failure, got %s", body)
	}
}

func TestSucceedIfSelfSignedCA(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	result := probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{
			TLSConfig: config.TLSConfig{InsecureSkipVerify: true},
		}}, registry)
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Fail if (not strict) selfsigned CA test fails unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re := regexp.MustCompile("probe_http_ssl 1")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected HTTP with SSL, got %s", body)
	}
}

func TestTLSConfigIsIgnoredForPlainHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	result := probeHTTP(ts.URL, recorder,
		Module{Timeout: time.Second, HTTP: HTTPProbe{
			TLSConfig: config.TLSConfig{InsecureSkipVerify: false},
		}}, registry)
	body := recorder.Body.String()
	if !result {
		t.Fatalf("Fail if InsecureSkipVerify affects simple http fails unexpectedly, got %s", body)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re := regexp.MustCompile("probe_http_ssl 0")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected HTTP without SSL, got %s", body)
	}

}
