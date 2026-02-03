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
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	promconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"

	"github.com/gorilla/websocket"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func TestCostructHeadersFromConfig(t *testing.T) {

	usernameFile := "/tmp/username_file_test"
	passwordFile := "/tmp/password_file_test"

	if err := os.WriteFile(usernameFile, []byte("user_from_file"), 0644); err != nil {
		t.Fatalf("Failed to create username file: %v", err)
	}
	defer os.Remove(usernameFile)

	if err := os.WriteFile(passwordFile, []byte("password_from_file"), 0644); err != nil {
		t.Fatalf("Failed to create password file: %v", err)
	}
	defer os.Remove(passwordFile)

	headerFile := "/tmp/header_file_test"
	if err := os.WriteFile(headerFile, []byte("header_value_from_file"), 0644); err != nil {
		t.Fatalf("Failed to create header file: %v", err)
	}
	defer os.Remove(headerFile)

	logger := promslog.NewNopLogger()
	testConfig := config.WebsocketProbe{
		HTTPClientConfig: promconfig.HTTPClientConfig{
			BasicAuth: &promconfig.BasicAuth{
				Username: "user",
				Password: "password",
			},
		},
		Headers: promconfig.Headers{
			Headers: map[string]promconfig.Header{
				"X-Custom-Header": {
					Values: []string{"custom_value"},
				},
			},
		},
	}
	testCases := []map[string]interface{}{
		{
			"test": testConfig,
			"expected": map[string][]string{
				"Authorization":   {"Basic " + base64.StdEncoding.EncodeToString([]byte("user:password"))},
				"X-Custom-Header": {"custom_value"},
			},
		},
		{
			"test": config.WebsocketProbe{
				HTTPClientConfig: promconfig.HTTPClientConfig{
					BasicAuth: &promconfig.BasicAuth{
						UsernameFile: usernameFile,
						PasswordFile: passwordFile,
					},
				},
			},
			"expected": map[string][]string{
				"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("user_from_file:password_from_file"))},
			},
		},
		{
			"test": config.WebsocketProbe{
				Headers: promconfig.Headers{
					Headers: map[string]promconfig.Header{
						"X-Header-From-File": {
							Files: []string{headerFile},
						},
					},
				},
			},
			"expected": map[string][]string{
				"X-Header-From-File": {"header_value_from_file"},
			},
		},
	}
	for _, tc := range testCases {
		actual := constructHeadersFromConfig(tc["test"].(config.WebsocketProbe), logger)
		expected := tc["expected"].(map[string][]string)
		if !reflect.DeepEqual(actual, expected) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	}
}

func TestProbeWebsocket(t *testing.T) {

	regexp_1, err := config.NewRegexp("incoming_(.+)")
	if err != nil {
		t.Errorf("Failed to create regexp: %v", err)
	}
	regexp_2, err := config.NewRegexp("^passed")
	if err != nil {
		t.Errorf("Failed to create regexp: %v", err)
	}
	regexp_3, err := config.NewRegexp("^someotherstring")
	if err != nil {
		t.Errorf("Failed to create regexp: %v", err)
	}

	type testCase struct {
		url             string
		module          config.Module
		expected        map[string]float64
		expectedSuccess bool
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var upgrader = websocket.Upgrader{}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()

		conn.WriteMessage(websocket.TextMessage, []byte("incoming_test"))
		_, message, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("Failed to read message: %v", err)
			return
		}
		if string(message) != "outgoing_test" {
			t.Errorf("Expected: %v, got: %v", "outgoing_test", string(message))
		}
		conn.WriteMessage(websocket.TextMessage, []byte("passed"))

	}))
	defer s.Close()
	url := strings.Replace(s.URL, "http://", "ws://", 1)

	// Test with TLS. To check that certificate checking is skipped
	s_ssl := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var upgrader = websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()
	}))
	defer s_ssl.Close()
	s_url := strings.Replace(s_ssl.URL, "https://", "wss://", 1)

	testCases := []testCase{
		{
			url: url,
			module: config.Module{
				Websocket: config.WebsocketProbe{
					IPProtocolFallback: true,
					QueryResponse: []config.QueryResponse{
						{
							Expect: regexp_1,
							Send:   "outgoing_${1}",
						},
						{
							Expect: regexp_2,
						},
					},
				},
			},
			expected: map[string]float64{
				"probe_websocket_status_code":         101,
				"probe_websocket_connection_upgraded": 1,
				"probe_websocket_failed_due_to_regex": 0,
			},
			expectedSuccess: true,
		},
		{
			url: url,
			module: config.Module{
				Websocket: config.WebsocketProbe{
					IPProtocolFallback: true,
					QueryResponse: []config.QueryResponse{
						{
							Expect: regexp_1,
							Send:   "outgoing_${1}",
						},
						{
							Expect: regexp_3,
						},
					},
				},
			},
			expected: map[string]float64{
				"probe_websocket_status_code":         101,
				"probe_websocket_connection_upgraded": 1,
				"probe_websocket_failed_due_to_regex": 1,
			},
			expectedSuccess: false,
		},
		{
			url: s_url,
			module: config.Module{
				Websocket: config.WebsocketProbe{
					IPProtocolFallback: true,
					HTTPClientConfig: promconfig.HTTPClientConfig{
						Authorization: &promconfig.Authorization{
							Credentials: "test_token",
						},
						TLSConfig: promconfig.TLSConfig{InsecureSkipVerify: true},
					},
					Headers: promconfig.Headers{
						Headers: map[string]promconfig.Header{
							"X-Should-Be-Sent": {
								Values: []string{"true"},
							},
						},
					},
				},
			},
			expected: map[string]float64{
				"probe_websocket_status_code":         101,
				"probe_websocket_connection_upgraded": 1,
			},
			expectedSuccess: true,
		},
		{
			url: url,
			module: config.Module{
				Websocket: config.WebsocketProbe{
					IPProtocol:         "ip4",
					IPProtocolFallback: true,
					QueryResponse: []config.QueryResponse{
						{
							Expect: regexp_1,
							Send:   "outgoing_${1}",
						},
						{
							Expect: regexp_2,
						},
					},
				},
			},
			expected: map[string]float64{
				"probe_websocket_status_code":         101,
				"probe_websocket_connection_upgraded": 1,
				"probe_websocket_failed_due_to_regex": 0,
			},
			expectedSuccess: true,
		},
	}

	log := promslog.NewNopLogger()

	for _, tc := range testCases {
		registry := prometheus.NewRegistry()
		ctx := context.Background()

		success := ProbeWebsocket(ctx, tc.url, tc.module, registry, log)

		if success != tc.expectedSuccess {
			t.Errorf("Expected success: %v, got: %v", tc.expectedSuccess, success)
		}

		mf, err := registry.Gather()
		if err != nil {
			t.Errorf("Failed to gather metrics: %v", err)
		}

		checkRegistryResults(tc.expected, mf, t)

		// Verify duration metrics exist and are non-negative
		for _, metric := range mf {
			if metric.GetName() == "probe_websocket_duration_seconds" {
				if len(metric.Metric) == 0 {
					t.Errorf("probe_websocket_duration_seconds has no metrics")
				}
				for _, m := range metric.Metric {
					if m.GetGauge().GetValue() < 0 {
						t.Errorf("probe_websocket_duration_seconds has negative value")
					}
					foundPhase := false
					for _, label := range m.GetLabel() {
						if label.GetName() == "phase" {
							foundPhase = true
							if label.GetValue() == "" {
								t.Errorf("probe_websocket_duration_seconds has empty phase label")
							}
						}
					}
					if !foundPhase {
						t.Errorf("probe_websocket_duration_seconds missing phase label")
					}
				}
			}
		}
	}

}
