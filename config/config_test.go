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

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.yaml.in/yaml/v3"
)

func TestLoad(t *testing.T) {
	cfg, err := Load([]byte(`
modules:
  http_2xx:
    prober: http
    timeout: 5s
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Modules["http_2xx"].HTTP.IPProtocolFallback; !got {
		t.Fatal("Load() did not apply HTTP probe defaults")
	}

	if _, err := Load([]byte("modules:\n  broken:\n    prober: invalid\n")); err == nil {
		t.Fatal("Load() succeeded with an invalid prober")
	}
	if _, err := Load([]byte("unknown: true\n")); err == nil {
		t.Fatal("Load() succeeded with an unknown field")
	}
}

func TestLoadNormalizesDeprecatedFields(t *testing.T) {
	cfg, err := Load([]byte(`
modules:
  http:
    prober: http
    http:
      no_follow_redirects: true
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	module := cfg.Modules["http"]
	if module.HTTP.NoFollowRedirects != nil {
		t.Fatal("Load() retained deprecated no_follow_redirects")
	}
	if module.HTTP.HTTPClientConfig.FollowRedirects {
		t.Fatal("Load() did not apply no_follow_redirects")
	}
}

func TestProgrammaticValidationNormalizesDeprecatedFields(t *testing.T) {
	noFollowRedirects := true
	module := NewModuleWithDefaults("http")
	module.HTTP.NoFollowRedirects = &noFollowRedirects
	cfg := ModulesConfig{Modules: map[string]Module{"http": module}}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	module = cfg.Modules["http"]
	if module.HTTP.NoFollowRedirects != nil {
		t.Fatal("Validate() retained deprecated no_follow_redirects")
	}
	if module.HTTP.HTTPClientConfig.FollowRedirects {
		t.Fatal("Validate() did not apply no_follow_redirects")
	}
}

func TestProgrammaticModuleDefaultsMatchYAML(t *testing.T) {
	loaded, err := Load([]byte(`
modules:
  http:
    prober: http
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	programmatic := ModulesConfig{Modules: map[string]Module{
		"http": NewModuleWithDefaults("http"),
	}}
	if err := programmatic.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if got, want := programmatic.Modules["http"], loaded.Modules["http"]; !reflect.DeepEqual(got, want) {
		t.Errorf("programmatic module does not match YAML module:\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestConfigValidateProgrammatic(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ModulesConfig
		wantErr string
	}{
		{
			name: "valid",
			cfg: ModulesConfig{Modules: map[string]Module{
				"http_2xx": {
					Prober: "http",
					HTTP:   DefaultHTTPProbe,
				},
			}},
		},
		{
			name: "invalid prober",
			cfg: ModulesConfig{Modules: map[string]Module{
				"broken": {Prober: "invalid"},
			}},
			wantErr: "module \"broken\": prober 'invalid' is not valid",
		},
		{
			name: "invalid DNS",
			cfg: ModulesConfig{Modules: map[string]Module{
				"dns": {Prober: "dns", DNS: DefaultDNSProbe},
			}},
			wantErr: "module \"dns\": query name must be set for DNS module",
		},
		{
			name: "uninitialized body match regexp",
			cfg: ModulesConfig{Modules: map[string]Module{
				"http": {
					Prober: "http",
					HTTP: HTTPProbe{
						FailIfBodyMatchesRegexp: []Regexp{{}},
					},
				},
			}},
			wantErr: "module \"http\": fail_if_body_matches_regexp[0]: regexp must be initialized",
		},
		{
			name: "uninitialized body not match regexp",
			cfg: ModulesConfig{Modules: map[string]Module{
				"http": {
					Prober: "http",
					HTTP: HTTPProbe{
						FailIfBodyNotMatchesRegexp: []Regexp{{}},
					},
				},
			}},
			wantErr: "module \"http\": fail_if_body_not_matches_regexp[0]: regexp must be initialized",
		},
		{
			name: "uninitialized body match CEL program",
			cfg: ModulesConfig{Modules: map[string]Module{
				"http": {
					Prober: "http",
					HTTP: HTTPProbe{
						FailIfBodyJSONMatchesCEL: &CELProgram{},
					},
				},
			}},
			wantErr: "module \"http\": fail_if_body_json_matches_cel: CEL program must be initialized",
		},
		{
			name: "uninitialized body not match CEL program",
			cfg: ModulesConfig{Modules: map[string]Module{
				"http": {
					Prober: "http",
					HTTP: HTTPProbe{
						FailIfBodyJSONNotMatchesCEL: &CELProgram{},
					},
				},
			}},
			wantErr: "module \"http\": fail_if_body_json_not_matches_cel: CEL program must be initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("Validate() error = %v; want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	sc := NewSafeConfig(prometheus.NewRegistry())

	err := sc.ReloadConfig("testdata/blackbox-good.yml", nil)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "blackbox.yml", err)
	}
}

func TestReloadConfigRejectsMultipleDocuments(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "blackbox.yml")
	if err := os.WriteFile(configFile, []byte(`
modules:
  http:
    prober: http
---
modules:
  another:
    prober: http
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	sc := NewSafeConfig(prometheus.NewRegistry())
	err := sc.ReloadConfig(configFile, nil)
	if err == nil || !strings.Contains(err.Error(), "configuration must contain exactly one YAML document") {
		t.Fatalf("ReloadConfig() error = %v; want multiple-document error", err)
	}
}

func TestLoadBadConfigs(t *testing.T) {
	sc := NewSafeConfig(prometheus.NewRegistry())
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "testdata/blackbox-bad.yml",
			want:  "error parsing config file: yaml: unmarshal errors:\n  line 50: field invalid_extra_field not found in type config.plain",
		},
		{
			input: "testdata/blackbox-bad2.yml",
			want:  "error parsing config file: at most one of bearer_token & bearer_token_file must be configured",
		},
		{
			input: "testdata/invalid-prober.yml",
			want:  "error parsing config file: prober 'invalid' is not valid",
		},
		{
			input: "testdata/invalid-dns-module.yml",
			want:  "error parsing config file: query name must be set for DNS module",
		},
		{
			input: "testdata/invalid-dns-class.yml",
			want:  "error parsing config file: query class 'X' is not valid",
		},
		{
			input: "testdata/invalid-dns-type.yml",
			want:  "error parsing config file: query type 'X' is not valid",
		},
		{
			input: "testdata/invalid-http-header-match.yml",
			want:  "error parsing config file: regexp must be set for HTTP header matchers",
		},
		{
			input: "testdata/invalid-http-body-match-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-http-body-not-match-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-http-header-match-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-http-compression-mismatch.yml",
			want:  `error parsing config file: invalid configuration "Accept-Encoding: deflate", "compression: gzip"`,
		},
		{
			input: "testdata/invalid-http-compression-mismatch-special-case.yml",
			want:  `error parsing config file: invalid configuration "accEpt-enCoding: deflate", "compression: gzip"`,
		},
		{
			input: "testdata/invalid-http-request-compression-reject-all-encodings.yml",
			want:  `error parsing config file: invalid configuration "Accept-Encoding: *;q=0.0", "compression: gzip"`,
		},
		{
			input: "testdata/invalid-http-http3-http2.yml",
			want:  "error parsing config file: HTTP/3 and HTTP/2.0/1.1 cannot be used together - only HTTP/3.0 is allowed when enable_http3 is true",
		},
		{
			input: "testdata/invalid-no-versions-http3-enabled.yml",
			want:  "error parsing config file: when enable_http3 is true, enable_http2 must be set to false",
		},
		{
			input: "testdata/invalid-http-http3-http2-version.yml",
			want:  "error parsing config file: HTTP/3 and HTTP/2.0/1.1 cannot be used together - only HTTP/3.0 is allowed when enable_http3 is true",
		},
		{
			input: "testdata/invalid-http-http3-http2-enabled.yml",
			want:  "error parsing config file: when enable_http3 is true, enable_http2 must be set to false",
		},
		{
			input: "testdata/invalid-icmp-ttl.yml",
			want:  "error parsing config file: \"ttl\" cannot be negative",
		},
		{
			input: "testdata/invalid-icmp-ttl-overflow.yml",
			want:  "error parsing config file: \"ttl\" cannot exceed 255",
		},
		{
			input: "testdata/invalid-tcp-query-response-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-unix-query-response-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-websocket-query-response-regexp.yml",
			want:  `error parsing config file: "Could not compile regular expression" regexp=":["`,
		},
		{
			input: "testdata/invalid-http-body-config.yml",
			want:  `error parsing config file: setting body and body_file both are not allowed`,
		},
		{
			input: "testdata/invalid-tcp-check-revoked-without-tls.yml",
			want:  `error parsing config file: check_revoked cannot be used when tls is false and no query_response step uses starttls`,
		},
		{
			input: "testdata/invalid-grpc-check-revoked-without-tls.yml",
			want:  `error parsing config file: check_revoked cannot be used when tls is false`,
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got := sc.ReloadConfig(test.input, nil)
			if got == nil || got.Error() != test.want {
				t.Fatalf("ReloadConfig(%q) = %v; want %q", test.input, got, test.want)
			}
		})
	}
}

func TestHideConfigSecrets(t *testing.T) {
	sc := NewSafeConfig(prometheus.NewRegistry())

	err := sc.ReloadConfig("testdata/blackbox-good.yml", nil)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/blackbox-good.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshalling config: %v", err)
	}
	if strings.Contains(string(c), "mysecret") {
		t.Fatal("config's String method reveals authentication credentials.")
	}
}

func TestIsEncodingAcceptable(t *testing.T) {
	testcases := map[string]struct {
		input          string
		acceptEncoding string
		expected       bool
	}{
		"empty compression": {
			input:          "",
			acceptEncoding: "gzip",
			expected:       true,
		},
		"trivial": {
			input:          "gzip",
			acceptEncoding: "gzip",
			expected:       true,
		},
		"trivial, quality": {
			input:          "gzip",
			acceptEncoding: "gzip;q=1.0",
			expected:       true,
		},
		"first": {
			input:          "gzip",
			acceptEncoding: "gzip, compress",
			expected:       true,
		},
		"second": {
			input:          "gzip",
			acceptEncoding: "compress, gzip",
			expected:       true,
		},
		"missing": {
			input:          "br",
			acceptEncoding: "gzip, compress",
			expected:       false,
		},
		"*": {
			input:          "br",
			acceptEncoding: "gzip, compress, *",
			expected:       true,
		},
		"* with quality": {
			input:          "br",
			acceptEncoding: "gzip, compress, *;q=0.1",
			expected:       true,
		},
		"rejected": {
			input:          "br",
			acceptEncoding: "gzip, compress, br;q=0.0",
			expected:       false,
		},
		"rejected *": {
			input:          "br",
			acceptEncoding: "gzip, compress, *;q=0.0",
			expected:       false,
		},
		"complex": {
			input:          "br",
			acceptEncoding: "gzip;q=1.0, compress;q=0.5, br;q=0.1, *;q=0.0",
			expected:       true,
		},
		"complex out of order": {
			input:          "br",
			acceptEncoding: "*;q=0.0, compress;q=0.5, br;q=0.1, gzip;q=1.0",
			expected:       true,
		},
		"complex with extra blanks": {
			input:          "br",
			acceptEncoding: " gzip;q=1.0, compress; q=0.5, br;q=0.1, *; q=0.0 ",
			expected:       true,
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			actual := isCompressionAcceptEncodingValid(tc.input, tc.acceptEncoding)
			if actual != tc.expected {
				t.Errorf("Unexpected result: input=%q acceptEncoding=%q expected=%t actual=%t", tc.input, tc.acceptEncoding, tc.expected, actual)
			}
		})
	}
}

func TestNewCELProgram(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "valid expression",
			expr:    "body.foo == 'bar'",
			wantErr: false,
		},
		{
			name:    "invalid expression",
			expr:    "foo.bar",
			wantErr: true,
		},
		{
			name:    "empty expression",
			expr:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCELProgram(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCELProgram() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestWebsocketProbeUnmarshal(t *testing.T) {
	configStr := `
modules:
  websocket_test:
    prober: websocket
    websocket:
      http_config:
        tls_config:
          insecure_skip_verify: true
        basic_auth:
          username: myuser
          password: mypassword
`
	sc := NewSafeConfig(prometheus.NewRegistry())
	if err := yaml.Unmarshal([]byte(configStr), &sc.C); err != nil {
		t.Fatalf("Error unmarshalling config: %v", err)
	}

	module, ok := sc.C.Modules["websocket_test"]
	if !ok {
		t.Fatal("Module 'websocket_test' not found")
	}

	if !module.Websocket.HTTPClientConfig.TLSConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}
	if module.Websocket.HTTPClientConfig.BasicAuth.Username != "myuser" {
		t.Errorf("Expected username 'myuser', got '%s'", module.Websocket.HTTPClientConfig.BasicAuth.Username)
	}
}
