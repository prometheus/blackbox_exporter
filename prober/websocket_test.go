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
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"

	"github.com/gorilla/websocket"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func TestCostructHeadersFromConfig(t *testing.T) {

	logger := promslog.NewNopLogger()
	testConfig := &config.WSHTTPClientConfig{
		BasicAuth: config.HTTPBasicAuth{
			Username: "user",
			Password: "password",
		},
		BearerToken: "testbearer_token",
		HTTPHeaders: map[string]interface{}{
			"test":  "test",
			"test2": []string{"test", "test2"},
		},
	}
	testCases := []map[string]interface{}{
		{
			"test": testConfig,
			"expected": map[string][]string{
				"Authorization": {(&config.HTTPBasicAuth{Username: "user", Password: "password"}).BasicAuthHeader()},
				"Test":          {"test"},
				"Test2":         {"test", "test2"},
			},
		},
	}
	for _, tc := range testCases {
		actual := constructHeadersFromConfig(tc["test"].(*config.WSHTTPClientConfig), logger)
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
		url      string
		module   config.Module
		expected map[string]float64
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
		},
		{
			url: url,
			module: config.Module{
				Websocket: config.WebsocketProbe{
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
		},
		{
			url: s_url,
			module: config.Module{
				Websocket: config.WebsocketProbe{
					WSHTTPClientConfig: config.WSHTTPClientConfig{
						BearerToken: "test_token",
						TLSConfig:   &tls.Config{InsecureSkipVerify: true},
					},
				},
			},
			expected: map[string]float64{
				"probe_websocket_status_code":         101,
				"probe_websocket_connection_upgraded": 1,
			},
		},
	}

	log := promslog.NewNopLogger()

	for _, tc := range testCases {
		registry := prometheus.NewRegistry()
		ctx := context.Background()

		success := ProbeWebsocket(ctx, tc.url, tc.module, registry, log)
		if !success {
			t.Errorf("Failed to probe websocket")
		}

		mf, err := registry.Gather()
		if err != nil {
			t.Errorf("Failed to gather metrics: %v", err)
		}

		checkRegistryResults(tc.expected, mf, t)
	}

}
