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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestIncludeResponseBodyInDebugOutput(t *testing.T) {
	expectedBody := `Service Health Check
Database: ok
Cache: ok
Queue: CRITICAL - Connection refused
External API: ok`

	tests := []struct {
		name                string
		includeResponseBody bool
		shouldContainBody   bool
		description         string
	}{
		{
			name:                "IncludeEnabled",
			includeResponseBody: true,
			shouldContainBody:   true,
			description:         "When include_response_body is true, body should be captured",
		},
		{
			name:                "IncludeDisabled",
			includeResponseBody: false,
			shouldContainBody:   false,
			description:         "When include_response_body is false, body should not be captured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test HTTP server that returns health check response
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(expectedBody))
			}))
			defer ts.Close()

			// Create module with include_response_body option
			module := config.Module{
				Timeout: time.Second,
				HTTP: config.HTTPProbe{
					IPProtocolFallback:  true,
					IncludeResponseBody: tt.includeResponseBody,
				},
			}

			// Run probe
			registry := prometheus.NewRegistry()
			logBuffer := &bytes.Buffer{}
			logger := promslog.New(&promslog.Config{Writer: logBuffer})

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := ProbeHTTP(testCTX, ts.URL, module, registry, logger)

			if !result {
				t.Fatalf("Probe failed unexpectedly")
			}

			// Get debug output
			debugOutput := DebugOutput(&module, logBuffer, registry)

			// Check if response body is in debug output
			// The body appears in logs with escaped newlines or the actual content
			containsBody := strings.Contains(debugOutput, "Service Health Check") &&
				strings.Contains(debugOutput, "Database: ok") &&
				strings.Contains(debugOutput, "Queue: CRITICAL - Connection refused")

			if tt.shouldContainBody && !containsBody {
				t.Errorf("%s: Expected response body in debug output but it was not found.\nDebug output:\n%s", tt.description, debugOutput)
			}

			if !tt.shouldContainBody && containsBody {
				t.Errorf("%s: Response body should not be in debug output but it was found.\nDebug output:\n%s", tt.description, debugOutput)
			}

			// Verify debug output has the expected log entry when body is included
			if tt.shouldContainBody {
				if !strings.Contains(debugOutput, "Response Body:") {
					t.Errorf("Expected 'Response Body:' in debug output")
				}
			}
		})
	}
}

func TestResponseBodySizeLimit(t *testing.T) {
	// Create a large response body (>64KB)
	largeBody := strings.Repeat("X", 70000)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeBody))
	}))
	defer ts.Close()

	module := config.Module{
		Timeout: time.Second,
		HTTP: config.HTTPProbe{
			IPProtocolFallback:  true,
			IncludeResponseBody: true,
		},
	}

	registry := prometheus.NewRegistry()
	logBuffer := &bytes.Buffer{}
	logger := promslog.New(&promslog.Config{Writer: logBuffer})

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := ProbeHTTP(testCTX, ts.URL, module, registry, logger)

	if !result {
		t.Fatalf("Probe failed unexpectedly")
	}

	debugOutput := DebugOutput(&module, logBuffer, registry)

	// Body should be truncated to max 64KB
	// Check that we got some body but not all of it
	if strings.Contains(debugOutput, largeBody) {
		t.Error("Large response body was not truncated")
	}

	// Should still contain the beginning of the body
	if !strings.Contains(debugOutput, strings.Repeat("X", 100)) {
		t.Error("Response body should contain at least the first part of the large body")
	}
}

func TestResponseBodyWithDifferentContentTypes(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		checkString string // A substring that should definitely be in the output
	}{
		{
			name:        "JSON",
			contentType: "application/json",
			body:        `{"status": "healthy", "components": {"db": "ok", "cache": "ok"}}`,
			checkString: "healthy",
		},
		{
			name:        "PlainText",
			contentType: "text/plain",
			body:        "Service is healthy",
			checkString: "Service is healthy",
		},
		{
			name:        "HTML",
			contentType: "text/html",
			body:        "<html><body><h1>Health OK</h1></body></html>",
			checkString: "Health OK",
		},
		{
			name:        "XML",
			contentType: "application/xml",
			body:        `<?xml version="1.0"?><health><status>ok</status></health>`,
			checkString: "<health>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tt.body))
			}))
			defer ts.Close()

			module := config.Module{
				Timeout: time.Second,
				HTTP: config.HTTPProbe{
					IPProtocolFallback:  true,
					IncludeResponseBody: true,
				},
			}

			registry := prometheus.NewRegistry()
			logBuffer := &bytes.Buffer{}
			logger := promslog.New(&promslog.Config{Writer: logBuffer})

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := ProbeHTTP(testCTX, ts.URL, module, registry, logger)

			if !result {
				t.Fatalf("Probe failed unexpectedly")
			}

			debugOutput := DebugOutput(&module, logBuffer, registry)

			if !strings.Contains(debugOutput, tt.checkString) {
				t.Errorf("Expected '%s' (%s) in debug output but it was not found.\nDebug output:\n%s", tt.checkString, tt.contentType, debugOutput)
			}
		})
	}
}
