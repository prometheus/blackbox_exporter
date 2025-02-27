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
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestHTTPStatusCodes(t *testing.T) {
	tests := []struct {
		StatusCode       int
		ValidStatusCodes []int
		expectedResult   ProbeResult
	}{
		{200, []int{}, ProbeSuccess()},
		{201, []int{}, ProbeSuccess()},
		{299, []int{}, ProbeSuccess()},
		{300, []int{}, ProbeFailure("Invalid HTTP response status code, wanted 2xx", "status_code", "300")},
		{404, []int{}, ProbeFailure("Invalid HTTP response status code, wanted 2xx", "status_code", "404")},
		{404, []int{200, 404}, ProbeSuccess()},
		{200, []int{200, 404}, ProbeSuccess()},
		{201, []int{200, 404}, ProbeFailure("Invalid HTTP response status code", "status_code", "201")},
		{404, []int{404}, ProbeSuccess()},
		{200, []int{404}, ProbeFailure("Invalid HTTP response status code", "status_code", "200")},
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
			config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, ValidStatusCodes: test.ValidStatusCodes}}, registry, promslog.NewNopLogger())
		if !reflect.DeepEqual(result, test.expectedResult) {
			t.Fatalf("Test %d had unexpected result: expected %s got %s", i, test.expectedResult, result)
			body := recorder.Body.String()
			t.Log(body)
		}
		body := recorder.Body.String()
		t.Log(body)
	}
}

func TestValidHTTPVersion(t *testing.T) {
	tests := []struct {
		ValidHTTPVersions []string
		expectedResult    ProbeResult
	}{
		{[]string{}, ProbeSuccess()},
		{[]string{"HTTP/1.1"}, ProbeSuccess()},
		{[]string{"HTTP/1.1", "HTTP/2.0"}, ProbeSuccess()},
		{[]string{"HTTP/2.0"}, ProbeFailure("Invalid HTTP version number", "version", "HTTP/1.1")},
	}
	for i, test := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		}))
		defer ts.Close()
		recorder := httptest.NewRecorder()
		registry := prometheus.NewRegistry()
		result := ProbeHTTP(context.Background(), ts.URL,
			config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
				IPProtocolFallback: true,
				ValidHTTPVersions:  test.ValidHTTPVersions,
			}}, registry, promslog.NewNopLogger())
		body := recorder.Body.String()
		if !reflect.DeepEqual(result, test.expectedResult) {
			t.Fatalf("Test %d had unexpected result: expected %s, got %s. %s", i, test.expectedResult, result, body)
		}
	}
}

func TestContentLength(t *testing.T) {
	type testdata struct {
		msg                    []byte
		contentLength          int
		uncompressedBodyLength int
		handler                http.HandlerFunc
		expectedResult         ProbeResult
	}

	testmsg := []byte(strings.Repeat("hello world", 10))

	notfoundMsg := []byte("not found")

	testcases := map[string]testdata{
		"identity": {
			expectedResult:         ProbeSuccess(),
			msg:                    testmsg,
			contentLength:          len(testmsg),
			uncompressedBodyLength: len(testmsg),
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Content-Encoding", "identity")
				w.WriteHeader(http.StatusOK)
				w.Write(testmsg)
			},
		},

		"no content-encoding": {
			expectedResult:         ProbeSuccess(),
			msg:                    testmsg,
			contentLength:          len(testmsg),
			uncompressedBodyLength: len(testmsg),
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(testmsg)
			},
		},

		// Unknown Content-Encoding, we should let this pass thru.
		"unknown content-encoding": {
			expectedResult:         ProbeSuccess(),
			msg:                    testmsg,
			contentLength:          len(testmsg),
			uncompressedBodyLength: len(testmsg),
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Content-Encoding", "xxx")
				w.WriteHeader(http.StatusOK)
				w.Write(bytes.Repeat([]byte{'x'}, len(testmsg)))
			},
		},

		// 401 response, verify that the content-length is still computed correctly.
		"401": {
			expectedResult:         ProbeFailure("Invalid HTTP response status code, wanted 2xx", "status_code", "404"),
			msg:                    notfoundMsg,
			contentLength:          len(notfoundMsg),
			uncompressedBodyLength: len(notfoundMsg),
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				// Send something in the body to make sure that this get reported as the content length.
				w.Write(notfoundMsg)
			},
		},

		// Compressed payload _without_ compression setting, it should not be decompressed.
		"brotli": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			fw := brotli.NewWriter(&buf)
			fw.Write([]byte(msg))
			fw.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				msg:                    msg,
				contentLength:          len(buf.Bytes()), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(buf.Bytes()), // No decompression.
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "br")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
			}
		}(),

		// Compressed payload _without_ compression setting, it should not be decompressed.
		"deflate": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			// the only error path is an invalid compression level
			fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
			fw.Write([]byte(msg))
			fw.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				msg:                    msg,
				contentLength:          len(buf.Bytes()), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(buf.Bytes()), // No decompression.
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "deflate")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
			}
		}(),

		// Compressed payload _without_ compression setting, it should not be decompressed.
		"gzip": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			gw.Write([]byte(msg))
			gw.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				msg:                    msg,
				contentLength:          len(buf.Bytes()), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(buf.Bytes()), // No decompression.
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "gzip")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
			}
		}(),
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			registry := prometheus.NewRegistry()
			var logbuf bytes.Buffer
			result := ProbeHTTP(testCTX,
				ts.URL,
				config.Module{
					Timeout: time.Second,
					HTTP:    config.HTTPProbe{IPProtocolFallback: true},
				},
				registry,
				promslog.New(&promslog.Config{Writer: &logbuf}))

			if !reflect.DeepEqual(result, tc.expectedResult) {
				t.Fatalf("Test had unexpected result: expected %v, got %v.", tc.expectedResult, result)
				t.Log(logbuf.String())
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}

			expectedResults := map[string]float64{
				"probe_http_content_length":           float64(tc.contentLength),
				"probe_http_uncompressed_body_length": float64(tc.uncompressedBodyLength),
			}
			checkRegistryResults(expectedResults, mfs, t)
		})
	}
}

// TestHandlingOfCompressionSetting verifies that the "compression"
// setting is handled correctly: content is decompressed only if
// compression is specified, and only the specified compression
// algorithm is handled.
func TestHandlingOfCompressionSetting(t *testing.T) {
	type testdata struct {
		contentLength          int
		uncompressedBodyLength int
		handler                http.HandlerFunc
		expectedResult         ProbeResult
		httpConfig             config.HTTPProbe
	}

	testmsg := []byte(strings.Repeat("hello world", 10))

	testcases := map[string]testdata{
		"gzip": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			enc := gzip.NewWriter(&buf)
			enc.Write(msg)
			enc.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				contentLength:          buf.Len(), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(msg),
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "gzip")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
				httpConfig: config.HTTPProbe{
					IPProtocolFallback: true,
					Compression:        "gzip",
				},
			}
		}(),

		"brotli": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			enc := brotli.NewWriter(&buf)
			enc.Write(msg)
			enc.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				contentLength:          len(buf.Bytes()), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(msg),
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "br")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
				httpConfig: config.HTTPProbe{
					IPProtocolFallback: true,
					Compression:        "br",
				},
			}
		}(),

		"deflate": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			// the only error path is an invalid compression level
			enc, _ := flate.NewWriter(&buf, flate.DefaultCompression)
			enc.Write(msg)
			enc.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				contentLength:          len(buf.Bytes()), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(msg),
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "deflate")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
				httpConfig: config.HTTPProbe{
					IPProtocolFallback: true,
					Compression:        "deflate",
				},
			}
		}(),

		"identity": {
			expectedResult:         ProbeSuccess(),
			contentLength:          len(testmsg),
			uncompressedBodyLength: len(testmsg),
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Content-Encoding", "identity")
				w.WriteHeader(http.StatusOK)
				w.Write(testmsg)
			},
			httpConfig: config.HTTPProbe{
				IPProtocolFallback: true,
				Compression:        "identity",
			},
		},

		// We do exactly as told: the server is returning a
		// gzip-encoded response, but the module is expecting a
		// delfate-encoded response. This should fail.
		"compression encoding mismatch": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			enc := gzip.NewWriter(&buf)
			enc.Write(msg)
			enc.Close()
			return testdata{
				expectedResult:         ProbeFailure("Failed to read HTTP response body"),
				contentLength:          buf.Len(), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: 0,
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "gzip")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
				httpConfig: config.HTTPProbe{
					IPProtocolFallback: true,
					Compression:        "deflate",
				},
			}
		}(),

		"accept gzip": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			enc := gzip.NewWriter(&buf)
			enc.Write(msg)
			enc.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				contentLength:          buf.Len(), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(msg),
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "gzip")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
				httpConfig: config.HTTPProbe{
					IPProtocolFallback: true,
					Compression:        "gzip",
					Headers: map[string]string{
						"Accept-Encoding": "gzip",
					},
				},
			}
		}(),

		"accept br, gzip": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			enc := gzip.NewWriter(&buf)
			enc.Write(msg)
			enc.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				contentLength:          buf.Len(), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(msg),
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "gzip")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
				httpConfig: config.HTTPProbe{
					IPProtocolFallback: true,
					Compression:        "gzip",
					Headers: map[string]string{
						"Accept-Encoding": "br, gzip",
					},
				},
			}
		}(),

		"accept anything": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			enc := gzip.NewWriter(&buf)
			enc.Write(msg)
			enc.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				contentLength:          buf.Len(), // Content length is the length of the compressed buffer.
				uncompressedBodyLength: len(msg),
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "gzip")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
				httpConfig: config.HTTPProbe{
					IPProtocolFallback: true,
					Compression:        "gzip",
					Headers: map[string]string{
						"Accept-Encoding": "*",
					},
				},
			}
		}(),

		"compressed content without compression setting": func() testdata {
			msg := testmsg
			var buf bytes.Buffer
			enc := gzip.NewWriter(&buf)
			enc.Write(msg)
			enc.Close()
			return testdata{
				expectedResult:         ProbeSuccess(),
				contentLength:          buf.Len(),
				uncompressedBodyLength: buf.Len(), // content won't be uncompressed
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Encoding", "gzip")
					w.WriteHeader(http.StatusOK)
					w.Write(buf.Bytes())
				},
				httpConfig: config.HTTPProbe{
					IPProtocolFallback: true,
				},
			}
		}(),
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			registry := prometheus.NewRegistry()
			var logbuf bytes.Buffer
			result := ProbeHTTP(testCTX,
				ts.URL,
				config.Module{
					Timeout: time.Second,
					HTTP:    tc.httpConfig,
				},
				registry,
				promslog.New(&promslog.Config{Writer: &logbuf}))
			if !reflect.DeepEqual(result, tc.expectedResult) {
				t.Fatalf("Test had unexpected result: expected %s, got %s", tc.expectedResult, result)
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}

			expectedResults := map[string]float64{
				"probe_http_content_length":           float64(tc.contentLength),
				"probe_http_uncompressed_body_length": float64(tc.uncompressedBodyLength),
			}
			checkRegistryResults(expectedResults, mfs, t)
		})
	}
}

func TestMaxResponseLength(t *testing.T) {
	const max = 128

	var shortGzippedPayload bytes.Buffer
	enc := gzip.NewWriter(&shortGzippedPayload)
	enc.Write(bytes.Repeat([]byte{'A'}, max-1))
	enc.Close()

	var longGzippedPayload bytes.Buffer
	enc = gzip.NewWriter(&longGzippedPayload)
	enc.Write(bytes.Repeat([]byte{'A'}, max+1))
	enc.Close()

	testcases := map[string]struct {
		target          string
		compression     string
		expectedMetrics map[string]float64
		expectedResult  ProbeResult
	}{
		"short": {
			expectedResult: ProbeSuccess(),
			target:         "/short",
			expectedMetrics: map[string]float64{
				"probe_http_uncompressed_body_length": float64(max - 1),
				"probe_http_content_length":           float64(max - 1),
			},
		},
		"long": {
			expectedResult: ProbeFailure("Failed to read HTTP response body"),
			target:         "/long",
			expectedMetrics: map[string]float64{
				"probe_http_content_length": float64(max + 1),
			},
		},
		"short compressed": {
			expectedResult: ProbeSuccess(),
			target:         "/short-compressed",
			compression:    "gzip",
			expectedMetrics: map[string]float64{
				"probe_http_content_length":           float64(shortGzippedPayload.Len()),
				"probe_http_uncompressed_body_length": float64(max - 1),
			},
		},
		"long compressed": {
			expectedResult: ProbeFailure("Failed to read HTTP response body"),
			target:         "/long-compressed",
			compression:    "gzip",
			expectedMetrics: map[string]float64{
				"probe_http_content_length":           float64(longGzippedPayload.Len()),
				"probe_http_uncompressed_body_length": max, // it should stop decompressing at max bytes
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp []byte

		switch r.URL.Path {
		case "/short-compressed":
			resp = shortGzippedPayload.Bytes()
			w.Header().Add("Content-Encoding", "gzip")

		case "/long-compressed":
			resp = longGzippedPayload.Bytes()
			w.Header().Add("Content-Encoding", "gzip")

		case "/long":
			resp = bytes.Repeat([]byte{'A'}, max+1)

		case "/short":
			resp = bytes.Repeat([]byte{'A'}, max-1)

		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}))
	defer ts.Close()

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := ProbeHTTP(
				testCTX,
				ts.URL+tc.target,
				config.Module{
					Timeout: time.Second,
					HTTP: config.HTTPProbe{
						IPProtocolFallback: true,
						BodySizeLimit:      max,
						HTTPClientConfig:   pconfig.DefaultHTTPClientConfig,
						Compression:        tc.compression,
					},
				},
				registry,
				promslog.NewNopLogger(),
			)

			if !reflect.DeepEqual(result, tc.expectedResult) {
				t.Fatalf("Test had unexpected result: expected %s, got %s", tc.expectedResult, result)
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}

			checkRegistryResults(tc.expectedMetrics, mfs, t)
		})
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
	result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, HTTPClientConfig: pconfig.DefaultHTTPClientConfig}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("Redirect test failed unexpectedly, got %s %s", result, body)
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
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, HTTPClientConfig: pconfig.HTTPClientConfig{FollowRedirects: false}, ValidStatusCodes: []int{302}}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("Redirect test failed unexpectedly, got %s %s", result, body)
	}

}

// TestRedirectionLimit verifies that the probe stops following
// redirects after some limit
func TestRedirectionLimit(t *testing.T) {
	const redirectLimit = 11

	tooManyRedirects := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == fmt.Sprintf("/redirect-%d", redirectLimit+1):
			// the client should never hit this path
			// because they should stop at the previous one.
			w.WriteHeader(http.StatusTooManyRequests)
			tooManyRedirects = true
			return

		case strings.HasPrefix(r.URL.Path, "/redirect-"):
			n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/redirect-"))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "failed to extract redirect number from %s", r.URL.Path)
				return
			}
			http.Redirect(w, r, fmt.Sprintf("/redirect-%d", n+1), http.StatusFound)

		default:
			http.Redirect(w, r, "/redirect-1", http.StatusFound)
		}
	}))
	defer ts.Close()

	// Follow redirect, should eventually fail with 302
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := ProbeHTTP(
		testCTX,
		ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, HTTPClientConfig: pconfig.DefaultHTTPClientConfig}},
		registry,
		promslog.NewNopLogger())
	if result.success {
		t.Fatalf("Probe succeeded unexpectedly, got %s", result)
	}

	if tooManyRedirects {
		t.Fatalf("Probe followed too many redirects")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := map[string]float64{
		"probe_http_redirects":   redirectLimit,    // should stop here
		"probe_http_status_code": http.StatusFound, // final code should be Found
	}
	checkRegistryResults(expectedResults, mfs, t)
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
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, Method: "POST"}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("Post test failed unexpectedly, got %s %s", result, body)
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
			IPProtocolFallback: true,
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: false},
				BasicAuth: &pconfig.BasicAuth{Username: "username", Password: "password"},
			},
		}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("HTTP probe failed, got %s %s", result, body)
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
			IPProtocolFallback: true,
			HTTPClientConfig: pconfig.HTTPClientConfig{
				BearerToken: pconfig.Secret("mysecret"),
			},
		}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("HTTP probe failed, got %s %s", result, body)
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
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfNotSSL: true}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	expectedResult := ProbeFailure("Final request was not over SSL")
	if !reflect.DeepEqual(result, expectedResult) {
		t.Fatalf("Test had unexpected result: expected %s, got %s %s", expectedResult, result, body)
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

func TestFailIfNotSSLLogMsg(t *testing.T) {
	const (
		Timeout = time.Second * 10
	)

	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer goodServer.Close()

	// Create a TCP server that closes the connection without an answer, to simulate failure.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	badServerURL := fmt.Sprintf("http://%s/", listener.Addr().String())

	for title, tc := range map[string]struct {
		Config         config.Module
		URL            string
		expectedResult ProbeResult
	}{
		"SSL expected, message": {
			Config:         config.Module{HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfNotSSL: true}},
			URL:            goodServer.URL,
			expectedResult: ProbeFailure("Final request was not over SSL"),
		},
		"No SSL expected, no message": {
			Config:         config.Module{HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfNotSSL: false}},
			URL:            goodServer.URL,
			expectedResult: ProbeSuccess(),
		},
		"SSL expected, no message": {
			Config:         config.Module{HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfNotSSL: true}},
			URL:            badServerURL,
			expectedResult: ProbeFailure("HTTP request failed"),
		},
	} {
		t.Run(title, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), Timeout)
			defer cancel()

			result := ProbeHTTP(testCTX, tc.URL, tc.Config, registry, promslog.NewNopLogger())
			if !reflect.DeepEqual(result, tc.expectedResult) {
				t.Fatalf("Test had unexpected result: expected %s, got %s", tc.expectedResult, result)
			}
		})
	}
}

func TestFailIfBodyMatchesCEL(t *testing.T) {
	testcases := map[string]struct {
		respBody       string
		celExpression  string
		expectedResult bool
	}{
		"celExpression matches": {
			respBody:       `{"foo": {"bar": "baz"}}`,
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: false,
		},
		"celExpression does not match": {
			respBody:       `{"foo": {"bar": "baz"}}`,
			celExpression:  "body.foo.bar == 'qux'",
			expectedResult: true,
		},
		"celExpression does not match with empty body": {
			respBody:       `{}`,
			celExpression:  "body.foo.bar == 'qux'",
			expectedResult: false,
		},
		"celExpression result not boolean": {
			respBody:       `{"foo": {"bar": "baz"}}`,
			celExpression:  "body.foo.bar",
			expectedResult: false,
		},
		"body is not json": {
			respBody:       "hello world",
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: false,
		},
		"body is empty json object": {
			respBody:       "{}",
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: false,
		},
		"body is json string": {
			respBody:       `"foo"`,
			celExpression:  "body == 'foo'",
			expectedResult: false,
		},
		"body is json list": {
			respBody:       `["foo","bar","baz"]`,
			celExpression:  "body[2] == 'baz'",
			expectedResult: false,
		},
		"body is json boolean": {
			respBody:       `true`,
			celExpression:  "body",
			expectedResult: false,
		},
		"body is empty": {
			respBody:       "",
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: false,
		},
		"body returns emoji": {
			respBody:       "🤠🤠🤠",
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: false,
		},
		"body returns json with emojis": {
			respBody:       `{"foo": {"bar": "🤠🤠🤠"}}`,
			celExpression:  "body.foo.bar == '😿😿😿'",
			expectedResult: true,
		},
	}

	for name, testcase := range testcases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, testcase.respBody)
			}))
			defer ts.Close()

			celProgram := config.MustNewCELProgram(testcase.celExpression)

			recorder := httptest.NewRecorder()
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfBodyJsonMatchesCEL: &celProgram}}, registry, promslog.NewNopLogger())
			if testcase.expectedResult && !result {
				t.Fatalf("CEL test failed unexpectedly, got %s", recorder.Body.String())
			} else if !testcase.expectedResult && result {
				t.Fatalf("CEL test succeeded unexpectedly, got %s", recorder.Body.String())
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			boolToFloat := func(v bool) float64 {
				if v {
					return 1
				}
				return 0
			}
			expectedResults := map[string]float64{
				"probe_failed_due_to_cel":             boolToFloat(!testcase.expectedResult),
				"probe_http_content_length":           float64(len(testcase.respBody)), // Issue #673: check that this is correctly populated when using regex validations.
				"probe_http_uncompressed_body_length": float64(len(testcase.respBody)), // Issue #673, see above.
			}
			checkRegistryResults(expectedResults, mfs, t)
		})
	}
}

func TestFailIfBodyNotMatchesCEL(t *testing.T) {
	testcases := map[string]struct {
		respBody       string
		celExpression  string
		expectedResult bool
	}{
		"cel matches": {
			respBody:       `{"foo": {"bar": "baz"}}`,
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: true,
		},
		"cel does not match": {
			respBody:       `{"foo": {"bar": "baz"}}`,
			celExpression:  "body.foo.bar == 'qux'",
			expectedResult: false,
		},
		"cel does not match with empty body": {
			respBody:       `{}`,
			celExpression:  "body.foo.bar == 'qux'",
			expectedResult: false,
		},
		"cel result not boolean": {
			respBody:       `{"foo": {"bar": "baz"}}`,
			celExpression:  "body.foo.bar",
			expectedResult: false,
		},
		"body is not json": {
			respBody:       "hello world",
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: false,
		},
		"body is empty json object": {
			respBody:       "{}",
			celExpression:  "!has(body.foo)",
			expectedResult: true,
		},
		"body is json string": {
			respBody:       `"foo"`,
			celExpression:  "body == 'foo'",
			expectedResult: true,
		},
		"body is json list": {
			respBody:       `["foo","bar","baz"]`,
			celExpression:  "body[2] == 'baz'",
			expectedResult: true,
		},
		"body is json boolean": {
			respBody:       `true`,
			celExpression:  "body",
			expectedResult: true,
		},
		"body is empty": {
			respBody:       "",
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: false,
		},
		"body returns emoji": {
			respBody:       "🤠🤠🤠",
			celExpression:  "body.foo.bar == 'baz'",
			expectedResult: false,
		},
		"body returns json with emojis": {
			respBody:       `{"foo": {"bar": "🤠🤠🤠"}}`,
			celExpression:  "body.foo.bar == '🤠🤠🤠'",
			expectedResult: true,
		},
	}

	for name, testcase := range testcases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, testcase.respBody)
			}))
			defer ts.Close()

			celProgram := config.MustNewCELProgram(testcase.celExpression)

			recorder := httptest.NewRecorder()
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfBodyJsonNotMatchesCEL: &celProgram}}, registry, promslog.NewNopLogger())
			if testcase.expectedResult && !result {
				t.Fatalf("CEL test failed unexpectedly, got %s", recorder.Body.String())
			} else if !testcase.expectedResult && result {
				t.Fatalf("CEL test succeeded unexpectedly, got %s", recorder.Body.String())
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			boolToFloat := func(v bool) float64 {
				if v {
					return 1
				}
				return 0
			}
			expectedResults := map[string]float64{
				"probe_failed_due_to_cel": boolToFloat(!testcase.expectedResult),
			}
			checkRegistryResults(expectedResults, mfs, t)
		})
	}
}

func TestFailIfBodyMatchesRegexp(t *testing.T) {
	testcases := map[string]struct {
		respBody       string
		regexps        []config.Regexp
		expectedResult ProbeResult
	}{
		"one regex, match": {
			respBody:       "Bad news: could not connect to database server",
			regexps:        []config.Regexp{config.MustNewRegexp("could not connect to database")},
			expectedResult: ProbeFailure("Body matched regular expression", "regexp", "could not connect to database"),
		},

		"one regex, no match": {
			respBody:       "Download the latest version here",
			regexps:        []config.Regexp{config.MustNewRegexp("could not connect to database")},
			expectedResult: ProbeSuccess(),
		},

		"multiple regexes, match": {
			respBody:       "internal error",
			regexps:        []config.Regexp{config.MustNewRegexp("could not connect to database"), config.MustNewRegexp("internal error")},
			expectedResult: ProbeFailure("Body matched regular expression", "regexp", "internal error"),
		},

		"multiple regexes, no match": {
			respBody:       "hello world",
			regexps:        []config.Regexp{config.MustNewRegexp("could not connect to database"), config.MustNewRegexp("internal error")},
			expectedResult: ProbeSuccess(),
		},
	}

	for name, testcase := range testcases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, testcase.respBody)
			}))
			defer ts.Close()

			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfBodyMatchesRegexp: testcase.regexps}}, registry, promslog.NewNopLogger())
			if !reflect.DeepEqual(result, testcase.expectedResult) {
				t.Fatalf("Test had unexpected result: expected %s, got %s", testcase.expectedResult, result)
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			boolToFloat := func(v bool) float64 {
				if v {
					return 1
				}
				return 0
			}
			expectedResults := map[string]float64{
				"probe_failed_due_to_regex":           boolToFloat(!testcase.expectedResult.success),
				"probe_http_content_length":           float64(len(testcase.respBody)), // Issue #673: check that this is correctly populated when using regex validations.
				"probe_http_uncompressed_body_length": float64(len(testcase.respBody)), // Issue #673, see above.
			}
			checkRegistryResults(expectedResults, mfs, t)
		})
	}
}

func TestFailIfBodyNotMatchesRegexp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Bad news: could not connect to database server")
	}))
	defer ts.Close()

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfBodyNotMatchesRegexp: []config.Regexp{config.MustNewRegexp("Download the latest version here")}}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	expectedResult := ProbeFailure("Body did not match regular expression", "regexp", "Download the latest version here")
	if !reflect.DeepEqual(result, expectedResult) {
		t.Fatalf("Test had unexpected result: expected %s, got %s %s", expectedResult, result, body)
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Download the latest version here")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfBodyNotMatchesRegexp: []config.Regexp{config.MustNewRegexp("Download the latest version here")}}}, registry, promslog.NewNopLogger())
	body = recorder.Body.String()
	if !result.success {
		t.Fatalf("Regexp test failed unexpectedly, got %s %s", result, body)
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
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfBodyNotMatchesRegexp: []config.Regexp{config.MustNewRegexp("Download the latest version here"), config.MustNewRegexp("Copyright 2015")}}}, registry, promslog.NewNopLogger())
	body = recorder.Body.String()
	expectedResult = ProbeFailure("Body did not match regular expression", "regexp", "Copyright 2015")
	if !reflect.DeepEqual(result, expectedResult) {
		t.Fatalf("Test had unexpected result: expected %s, got %s %s", expectedResult, result, body)
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Download the latest version here. Copyright 2015 Test Inc.")
	}))
	defer ts.Close()

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfBodyNotMatchesRegexp: []config.Regexp{config.MustNewRegexp("Download the latest version here"), config.MustNewRegexp("Copyright 2015")}}}, registry, promslog.NewNopLogger())
	body = recorder.Body.String()
	if !result.success {
		t.Fatalf("Regexp test failed unexpectedly, got %s %s", result, body)
	}
}

func TestFailIfHeaderMatchesRegexp(t *testing.T) {
	tests := []struct {
		Rule           config.HeaderMatch
		Values         []string
		expectedResult ProbeResult
	}{
		{
			config.HeaderMatch{Header: "Content-Type",
				Regexp:       config.MustNewRegexp("text/javascript"),
				AllowMissing: false},
			[]string{"text/javascript"},
			ProbeFailure("Header matched regular expression", "header", "Content-Type", "regexp", "text/javascript", "value_count", "1"),
		},
		{
			config.HeaderMatch{Header: "Content-Type",
				Regexp:       config.MustNewRegexp("text/javascript"),
				AllowMissing: false},
			[]string{"application/octet-stream"},
			ProbeSuccess(),
		},
		{
			config.HeaderMatch{Header: "content-type",
				Regexp:       config.MustNewRegexp("text/javascript"),
				AllowMissing: false},
			[]string{"application/octet-stream"},
			ProbeSuccess(),
		},
		{
			config.HeaderMatch{Header: "Content-Type",
				Regexp:       config.MustNewRegexp(".*"),
				AllowMissing: false},
			[]string{""},
			ProbeFailure("Header matched regular expression", "header", "Content-Type", "regexp", ".*", "value_count", "1"),
		},
		{
			config.HeaderMatch{Header: "Content-Type",
				Regexp:       config.MustNewRegexp(".*"),
				AllowMissing: false},
			[]string{},
			ProbeFailure("Missing required header", "header", "Content-Type"),
		},
		{
			config.HeaderMatch{Header: "Content-Type",
				Regexp:       config.MustNewRegexp(".*"),
				AllowMissing: true},
			[]string{""},
			ProbeFailure("Header matched regular expression", "header", "Content-Type", "regexp", ".*", "value_count", "1"),
		},
		{
			config.HeaderMatch{Header: "Content-Type",
				Regexp:       config.MustNewRegexp(".*"),
				AllowMissing: true},
			[]string{},
			ProbeSuccess(),
		},
		{
			config.HeaderMatch{Header: "Set-Cookie",
				Regexp:       config.MustNewRegexp(".*Domain=\\.example\\.com.*"),
				AllowMissing: false},
			[]string{"gid=1; Expires=Tue, 19-Mar-2019 20:08:29 GMT; Domain=.example.com; Path=/"},
			ProbeFailure("Header matched regular expression", "header", "Set-Cookie", "regexp", ".*Domain=\\.example\\.com.*", "value_count", "1"),
		},
		{
			config.HeaderMatch{Header: "Set-Cookie",
				Regexp:       config.MustNewRegexp(".*Domain=\\.example\\.com.*"),
				AllowMissing: false},
			[]string{"zz=4; expires=Mon, 01-Jan-1990 00:00:00 GMT; Domain=www.example.com; Path=/",
				"gid=1; Expires=Tue, 19-Mar-2019 20:08:29 GMT; Domain=.example.com; Path=/"},
			ProbeFailure("Header matched regular expression", "header", "Set-Cookie", "regexp", ".*Domain=\\.example\\.com.*", "value_count", "2"),
		},
	}

	for i, test := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, val := range test.Values {
				w.Header().Add(test.Rule.Header, val)
			}
		}))
		defer ts.Close()
		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfHeaderMatchesRegexp: []config.HeaderMatch{test.Rule}}}, registry, promslog.NewNopLogger())
		if !reflect.DeepEqual(result, test.expectedResult) {
			t.Fatalf("Test %d had unexpected result: expected %s, got %s", i, test.expectedResult, result)
		}

		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedResults := map[string]float64{
			"probe_failed_due_to_regex": 1,
		}

		if test.expectedResult.success {
			expectedResults["probe_failed_due_to_regex"] = 0
		}

		checkRegistryResults(expectedResults, mfs, t)
	}
}

func TestFailIfHeaderNotMatchesRegexp(t *testing.T) {
	tests := []struct {
		Rule           config.HeaderMatch
		Values         []string
		expectedResult ProbeResult
	}{
		{
			config.HeaderMatch{
				Header:       "Content-Type",
				Regexp:       config.MustNewRegexp("text/javascript"),
				AllowMissing: false,
			},

			[]string{"text/javascript"},
			ProbeSuccess(),
		},
		{
			config.HeaderMatch{
				Header:       "content-type",
				Regexp:       config.MustNewRegexp("text/javascript"),
				AllowMissing: false,
			},
			[]string{"text/javascript"},
			ProbeSuccess(),
		},
		{
			config.HeaderMatch{
				Header:       "Content-Type",
				Regexp:       config.MustNewRegexp("text/javascript"),
				AllowMissing: false,
			},
			[]string{"application/octet-stream"},
			ProbeFailure("Header did not match regular expression", "header", "Content-Type", "regexp", "text/javascript", "value_count", "1"),
		},
		{
			config.HeaderMatch{
				Header:       "Content-Type",
				Regexp:       config.MustNewRegexp(".*"),
				AllowMissing: false}, []string{""},
			ProbeSuccess(),
		},
		{
			config.HeaderMatch{
				Header:       "Content-Type",
				Regexp:       config.MustNewRegexp(".*"),
				AllowMissing: false},
			[]string{},
			ProbeFailure("Missing required header", "header", "Content-Type"),
		},
		{
			config.HeaderMatch{
				Header:       "Content-Type",
				Regexp:       config.MustNewRegexp(".*"),
				AllowMissing: true},
			[]string{},
			ProbeSuccess(),
		},
		{
			config.HeaderMatch{
				Header:       "Set-Cookie",
				Regexp:       config.MustNewRegexp(".*Domain=\\.example\\.com.*"),
				AllowMissing: false},
			[]string{"zz=4; expires=Mon, 01-Jan-1990 00:00:00 GMT; Domain=www.example.com; Path=/"},
			ProbeFailure("Header did not match regular expression", "header", "Set-Cookie", "regexp", ".*Domain=\\.example\\.com.*", "value_count", "1"),
		},
		{
			config.HeaderMatch{
				Header:       "Set-Cookie",
				Regexp:       config.MustNewRegexp(".*Domain=\\.example\\.com.*"),
				AllowMissing: false},
			[]string{"zz=4; expires=Mon, 01-Jan-1990 00:00:00 GMT; Domain=www.example.com; Path=/", "gid=1; Expires=Tue, 19-Mar-2019 20:08:29 GMT; Domain=.example.com; Path=/"},
			ProbeSuccess(),
		},
	}

	for i, test := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, val := range test.Values {
				w.Header().Add(test.Rule.Header, val)
			}
		}))
		defer ts.Close()
		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, FailIfHeaderNotMatchesRegexp: []config.HeaderMatch{test.Rule}}}, registry, promslog.NewNopLogger())
		if !reflect.DeepEqual(result, test.expectedResult) {
			t.Fatalf("Test %d had unexpected result: expected %s, got %s", i, test.expectedResult, result)
		}

		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedResults := map[string]float64{
			"probe_failed_due_to_regex": 1,
		}

		if test.expectedResult.success {
			expectedResults["probe_failed_due_to_regex"] = 0
		}

		checkRegistryResults(expectedResults, mfs, t)
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
			if textproto.CanonicalMIMEHeaderKey(key) == "Host" {
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
		IPProtocolFallback: true,
		Headers:            headers,
	}}, registry, promslog.NewNopLogger())
	if !result.success {
		t.Fatalf("Probe failed unexpectedly. %s", result)
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
			IPProtocolFallback: true,
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: false},
			},
		}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if result.success {
		t.Fatalf("Fail if selfsigned CA test succeeded unexpectedly, got %s %s", result, body)
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
			IPProtocolFallback: true,
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: true},
			},
		}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("Fail if (not strict) selfsigned CA test fails unexpectedly, got %s %s", result, body)
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
			IPProtocolFallback: true,
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: false},
			},
		}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("Fail if InsecureSkipVerify affects simple http fails unexpectedly, got %s %s", result, body)
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
	testCertTmpl := generateCertificateTemplate(certExpiry, false)
	testCertTmpl.IsCA = true
	_, testcertPem, testKey := generateSelfSignedCertificate(testCertTmpl)

	// CAFile must be passed via filesystem, use a tempfile.
	tmpCaFile, err := os.CreateTemp("", "cafile.pem")
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

	testKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)})
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
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			HTTPClientConfig: pconfig.HTTPClientConfig{
				TLSConfig: pconfig.TLSConfig{
					CAFile: tmpCaFile.Name(),
				},
			},
		},
	}

	// Replace IP address with hostname.
	url := strings.ReplaceAll(ts.URL, "127.0.0.1", "localhost")
	url = strings.ReplaceAll(url, "[::1]", "localhost")

	result := ProbeHTTP(context.Background(), url, module, registry, promslog.NewNopLogger())
	if !result.success {
		t.Fatalf("TLS probe failed unexpectedly, got %s", result)
	}
}

func TestRedirectToTLSHostWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network dependent test")
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://prometheus.io", http.StatusFound)
	}))
	defer ts.Close()

	// Follow redirect, should succeed with 200.
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeHTTP(testCTX, ts.URL,
		config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, HTTPClientConfig: pconfig.DefaultHTTPClientConfig}}, registry, promslog.NewNopLogger())
	if !result.success {
		t.Fatalf("Redirect test failed unexpectedly, got %s", result)
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
		IPProtocolFallback: true,
		HTTPClientConfig: pconfig.HTTPClientConfig{
			TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: true},
		},
	}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("HTTP Phases test failed unexpectedly, got %s %s", result, body)
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedMetrics := map[string]map[string]map[string]struct{}{
		"probe_http_duration_seconds": {
			"phase": {
				"connect":    {},
				"processing": {},
				"resolve":    {},
				"transfer":   {},
				"tls":        {},
			},
		},
	}

	checkMetrics(expectedMetrics, mfs, t)
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
	result := ProbeHTTP(testCTX, ts.URL, config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, HTTPClientConfig: pconfig.DefaultHTTPClientConfig}}, registry, promslog.NewNopLogger())
	body := recorder.Body.String()
	if !result.success {
		t.Fatalf("Redirect test failed unexpectedly, got %s %s", result, body)
	}
}

func TestSkipResolvePhase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network dependent test")
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	t.Run("Without Proxy", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result := ProbeHTTP(testCTX, ts.URL,
			config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, HTTPClientConfig: pconfig.DefaultHTTPClientConfig, SkipResolvePhaseWithProxy: true}}, registry, promslog.NewNopLogger())
		if !result.success {
			t.Fatalf("Probe unsuccessful %s", result)
		}
		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedMetrics := map[string]map[string]map[string]struct{}{
			"probe_http_duration_seconds": {
				"phase": {
					"connect":    {},
					"processing": {},
					"resolve":    {},
					"transfer":   {},
					"tls":        {},
				},
			},
		}

		checkMetrics(expectedMetrics, mfs, t)
	})
	t.Run("With Proxy", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpCfg := pconfig.DefaultHTTPClientConfig
		u, err := url.Parse("http://127.0.0.1:3128")
		if err != nil {
			t.Fatal(err.Error())
		}
		httpCfg.ProxyURL = pconfig.URL{
			URL: u,
		}
		ProbeHTTP(testCTX, ts.URL,
			config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, HTTPClientConfig: httpCfg, SkipResolvePhaseWithProxy: true}}, registry, promslog.NewNopLogger())
		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedMetrics := map[string]map[string]map[string]struct{}{
			"probe_http_duration_seconds": {
				"phase": {
					"connect":    {},
					"processing": {},
					"transfer":   {},
					"tls":        {},
				},
			},
		}

		checkMetrics(expectedMetrics, mfs, t)
	})
}

func TestBody(t *testing.T) {
	body := "Test Body"
	tmpBodyFile, err := os.CreateTemp("", "body.txt")
	if err != nil {
		t.Fatalf("Error creating body tempfile: %s", err)
	}
	if _, err := tmpBodyFile.Write([]byte(body)); err != nil {
		t.Fatalf("Error writing body tempfile: %s", err)
	}
	if err := tmpBodyFile.Close(); err != nil {
		t.Fatalf("Error closing body tempfie: %s", err)
	}

	tests := []config.HTTPProbe{
		{IPProtocolFallback: true, Body: body},
		{IPProtocolFallback: true, BodyFile: tmpBodyFile.Name()},
	}

	for i, test := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Body test %d failed unexpectedly.", i)
			}
			if string(b) != body {
				t.Fatalf("Body test %d failed unexpectedly.", i)
			}
		}))
		defer ts.Close()

		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result := ProbeHTTP(
			testCTX,
			ts.URL,
			config.Module{
				Timeout: time.Second,
				HTTP:    test},
			registry,
			promslog.NewNopLogger(),
		)
		if !result.success {
			t.Fatalf("Body test %d failed unexpectedly, got %s.", i, result)
		}
	}
}
