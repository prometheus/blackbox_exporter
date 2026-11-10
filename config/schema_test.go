// Copyright The Prometheus Authors
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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.yaml.in/yaml/v3"
)

var updateSchema = flag.Bool("update", false, "update blackbox.schema.json")

func TestJSONSchemaUpToDate(t *testing.T) {
	generated, err := generateJSONSchema(reflect.TypeFor[Config]())
	if err != nil {
		t.Fatal(err)
	}
	const filename = "../blackbox.schema.json"
	if *updateSchema {
		if err := os.WriteFile(filename, generated, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read schema: %v; run make schema", err)
	}
	if bytes.Equal(stored, generated) {
		return
	}
	oldLines := strings.Split(string(stored), "\n")
	for i, line := range strings.Split(string(generated), "\n") {
		if i >= len(oldLines) || oldLines[i] != line {
			t.Fatalf("schema is stale; run make schema\nfirst difference at line %d: expected %s", i+1, line)
		}
	}
	t.Fatal("schema is stale; run make schema (unexpected trailing lines)")
}

func loadJSONSchema(t *testing.T) schemaObject {
	t.Helper()
	data, err := generateJSONSchema(reflect.TypeFor[Config]())
	if err != nil {
		t.Fatal(err)
	}
	var doc schemaObject
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func resolveSchema(doc, node schemaObject) schemaObject {
	for ref, ok := node["$ref"].(string); ok; ref, ok = node["$ref"].(string) {
		node = doc["definitions"].(schemaObject)[strings.TrimPrefix(ref, "#/definitions/")].(schemaObject)
	}
	return node
}

func schemaTypes(node schemaObject) []any {
	if types, ok := node["type"].([]any); ok {
		return types
	}
	return []any{node["type"]}
}

func TestJSONSchemaPaths(t *testing.T) {
	doc := loadJSONSchema(t)
	if doc["$ref"] != nil || doc["properties"] == nil || doc["title"] == nil {
		t.Fatal("root must be an inline object with a title")
	}
	for _, name := range []string{"Config", "common.ProxyConfig"} {
		if _, exists := doc["definitions"].(schemaObject)[name]; exists {
			t.Errorf("unexpected unreferenced definition %s", name)
		}
	}
	for _, test := range []struct {
		path string
		kind string
	}{
		{"http.tls_config.min_version", "string"},
		{"http.valid_status_codes", "array"},
		{"http.valid_status_codes.[]", "integer"},
		{"http.fail_if_body_matches_regexp.[]", "string"},
		{"http.fail_if_body_json_matches_cel", "string"},
		{"timeout", "string"},
		{"http.basic_auth.password", "string"},
		{"http.authorization.credentials", "string"},
		{"http.bearer_token", "string"},
		{"http.proxy_url", "string"},
		{"http.proxy_connect_header.*.[]", "string"},
		{"http.follow_redirects", "boolean"},
		{"http.oauth2.tls_config", "object"},
		{"http.oauth2.proxy_url", "string"},
		{"http.oauth2.claims", "object"},
		{"http.headers.*", "string"},
		{"http.http_headers.*", "object"},
		{"http.http_headers.*.values.[]", "string"},
		{"websocket.http_config.http_headers.*.values", "array"},
		{"websocket.headers.*.values.[]", "string"},
		{"websocket.headers.*.secrets.[]", "string"},
		{"websocket.headers.*.files.[]", "string"},
		{"grpc.metadata", "object"},
		{"grpc.metadata.*.[]", "string"},
		{"dns.validate_answer_rrs.fail_if_matches_regexp.[]", "string"},
	} {
		t.Run(test.path, func(t *testing.T) {
			node := doc
			for step := range strings.SplitSeq("modules.*."+test.path, ".") {
				node = resolveSchema(doc, node)
				switch step {
				case "*":
					node, _ = node["additionalProperties"].(schemaObject)
				case "[]":
					node, _ = node["items"].(schemaObject)
				default:
					properties, _ := node["properties"].(schemaObject)
					node, _ = properties[step].(schemaObject)
				}
				if node == nil {
					t.Fatalf("missing schema at %s", step)
				}
			}
			node = resolveSchema(doc, node)
			if !slices.Contains(schemaTypes(node), any(test.kind)) {
				t.Errorf("type = %v; want %s", node["type"], test.kind)
			}
			if test.path == "http.tls_config.min_version" && !slices.Contains(node["enum"].([]any), any("TLS13")) {
				t.Error("TLS version enum must include TLS13")
			}
		})
	}
}

// validateSchema implements only the draft-07 keywords emitted by our generator.
func validateSchema(doc, node schemaObject, value any, location string) error {
	node = resolveSchema(doc, node)
	if integer, ok := value.(int); ok {
		value = float64(integer)
	}
	if alternatives, ok := node["anyOf"].([]any); ok {
		for _, alternative := range alternatives {
			if validateSchema(doc, alternative.(schemaObject), value, location) == nil {
				return nil
			}
		}
		return fmt.Errorf("%s: no anyOf alternative matches %v", location, value)
	}
	if constant, ok := node["const"]; ok && !reflect.DeepEqual(constant, value) {
		return fmt.Errorf("%s: want constant %v, got %v", location, constant, value)
	}
	if enum, ok := node["enum"].([]any); ok && !slices.Contains(enum, value) {
		return fmt.Errorf("%s: %v is not in enum %v", location, value, enum)
	}
	var kind string
	switch v := value.(type) {
	case nil:
		kind = "null"
	case map[string]any:
		kind = "object"
	case []any:
		kind = "array"
	case string:
		kind = "string"
	case bool:
		kind = "boolean"
	case float64:
		kind = "number"
		if v == math.Trunc(v) {
			kind = "integer"
		}
	default:
		return fmt.Errorf("%s: unsupported Go type %T", location, value)
	}
	types := schemaTypes(node)
	validType := slices.Contains(types, any(kind)) || kind == "integer" && slices.Contains(types, any("number"))
	if node["type"] != nil && !validType {
		return fmt.Errorf("%s: want %v, got %s", location, types, kind)
	}
	if pattern, ok := node["pattern"].(string); ok {
		if text, ok := value.(string); ok {
			matched, err := regexp.MatchString(pattern, text)
			if err != nil || !matched {
				return fmt.Errorf("%s: %q does not match %q: %v", location, text, pattern, err)
			}
		}
	}
	switch value := value.(type) {
	case map[string]any:
		properties, _ := node["properties"].(schemaObject)
		for key, child := range value {
			rule, ok := properties[key]
			if !ok {
				rule = node["additionalProperties"]
			}
			if allowed, ok := rule.(bool); ok && !allowed {
				return fmt.Errorf("%s.%s: unknown key", location, key)
			}
			if rule, ok := rule.(schemaObject); ok {
				if err := validateSchema(doc, rule, child, location+"."+key); err != nil {
					return err
				}
			}
		}
	case []any:
		if items, ok := node["items"].(schemaObject); ok {
			for i, child := range value {
				if err := validateSchema(doc, items, child, fmt.Sprintf("%s[%d]", location, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func schemaYAML(t *testing.T, data []byte) any {
	t.Helper()
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return normalizeSchemaYAML(value)
}

func normalizeSchemaYAML(value any) any {
	switch v := value.(type) {
	case map[any]any:
		object := map[string]any{}
		for key, child := range v {
			object[fmt.Sprint(key)] = normalizeSchemaYAML(child)
		}
		return object
	case map[string]any:
		for key, child := range v {
			v[key] = normalizeSchemaYAML(child)
		}
	case []any:
		for i, child := range v {
			v[i] = normalizeSchemaYAML(child)
		}
	}
	return value
}

func loadSchemaConfig(t *testing.T, data []byte) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "blackbox.yml")
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sc := NewSafeConfig(prometheus.NewRegistry())
	if err := sc.ReloadConfig(filename, nil); err != nil {
		t.Fatalf("exporter must accept this input: %v", err)
	}
}

func TestJSONSchemaCoversExampleConfigs(t *testing.T) {
	doc := loadJSONSchema(t)
	included := 0
	for _, pattern := range []string{"../*.yml", "testdata/*.yml"} {
		files, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, filename := range files {
			sc := NewSafeConfig(prometheus.NewRegistry())
			if err := sc.ReloadConfig(filename, nil); err != nil {
				continue
			}
			included++
			t.Logf("validating %s", filename)
			data, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSchema(doc, doc, schemaYAML(t, data), "$"); err != nil {
				t.Errorf("%s: %v", filename, err)
			}
		}
	}
	if included == 0 {
		t.Fatal("no accepted configuration examples found")
	}
}

func TestJSONSchemaRejectsInvalidConfigs(t *testing.T) {
	doc := loadJSONSchema(t)
	// Match yamllint's true/false rule and flag integer truncation and empty scalars.
	for _, test := range []struct {
		config, rejection string
		loadable          bool
	}{
		{"modules: {test: {http: {follow_redirect: true}}}", ".http.follow_redirect", false},
		{"modules: {test: {websocket: {headers: {X: {valuez: [test]}}}}}", ".websocket.headers.X.valuez", false},
		{"modules: {test: {http: {tls_config: {min_version: TLS14}}}}", ".http.tls_config.min_version", false},
		{`modules: {test: {http: {valid_status_codes: ["200"]}}}`, ".http.valid_status_codes[0]", false},
		{"modules: {test: {timeout: 5}}", ".timeout", false},
		{`modules: {test: {timeout: "5"}}`, ".timeout", false},
		{"modules: {test: {timeout: 1d}}", ".timeout", false},
		{"modules: {test: {http: {body_size_limit: 1024}}}", ".http.body_size_limit", false},
		{`modules: {test: {http: {body_size_limit: "1024"}}}`, ".http.body_size_limit", false},
		{"modules: {test: {prober: http, http: {follow_redirects: yes}}}", ".http.follow_redirects", true},
		{"modules: {test: {prober: http, http: {valid_status_codes: [200.5]}}}", ".http.valid_status_codes[0]", true},
		{"modules: {test: {prober: http, timeout: }}", ".timeout", true},
		{"modules: {1: {prober: http, htpt: {}}}", "$.modules.1.htpt", false},
	} {
		t.Run(test.config, func(t *testing.T) {
			data := []byte(test.config)
			if test.loadable {
				loadSchemaConfig(t, data)
			}
			err := validateSchema(doc, doc, schemaYAML(t, data), "$")
			if err == nil || !strings.Contains(err.Error(), test.rejection) {
				t.Fatalf("validation = %v; want rejection %q", err, test.rejection)
			}
		})
	}
}

func TestJSONSchemaAcceptsDecoderValues(t *testing.T) {
	doc := loadJSONSchema(t)
	for _, test := range []struct{ prober, config string }{
		{"", "modules: {1: {prober: http}}"},
		{"http", "timeout: 1m30s"},
		{"http", "timeout: 1.5h"},
		{"http", "http: {headers: {X-Api-Version: 2}}"},
		{"http", "http: {basic_auth: {password: 123456}}"},
		{"tcp", "tcp: {query_response: [{send: 220}]}"},
		{"grpc", "grpc: {service: 1}"},
		{"http", "http: {http_headers: {X: {values: [1, true]}}}"},
		{"http", "http: {headers: {X-Flag: true, X-Ratio: 1.5}}"},
		{"http", "http: {fail_if_body_matches_regexp: [123, true]}"},
		{"http", "http: {fail_if_body_json_matches_cel: false}"},
		{"http", "http: {proxy_url: 1}"},
		{"http", "http: {proxy_url: true}"},
		{"http", "http:\n  valid_status_codes:"},
		{"http", "http:"},
		{"http", "http: {body_size_limit: 1KiB512B}"},
		{"http", "http: {body_size_limit: -1MB}"},
		{"http", "http: {body_size_limit: 0B}"},
		{"http", `http: {body_size_limit: "1MB"}`},
		{"http", "http: {body_size_limit: 0}"},
		{"http", "http: {headers: null, http_headers: null}\ngrpc: {metadata: null}"},
	} {
		t.Run(test.config, func(t *testing.T) {
			data := []byte("modules:\n  test:\n    prober: " + test.prober + "\n    " +
				strings.ReplaceAll(test.config, "\n", "\n    ") + "\n")
			if test.prober == "" {
				data = []byte(test.config)
			}
			loadSchemaConfig(t, data)
			if err := validateSchema(doc, doc, schemaYAML(t, data), "$"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type schemaYAMLScalar string

func (schemaYAMLScalar) UnmarshalYAML(func(any) error) error { return nil }

type schemaNodeScalar int

func (*schemaNodeScalar) UnmarshalYAML(*yaml.Node) error { return nil }

type schemaTextScalar []byte

func (*schemaTextScalar) UnmarshalText([]byte) error { return nil }

type schemaPlain struct {
	Value string `yaml:"value"`
}

func (*schemaPlain) UnmarshalYAML(func(any) error) error { return nil }

func TestJSONSchemaUnsupportedTypes(t *testing.T) {
	if err := validateSchema(nil, schemaObject{"type": "null"}, struct{}{}, "$"); err == nil || !strings.Contains(err.Error(), "unsupported Go type") {
		t.Errorf("validator must reject unsupported Go values: %v", err)
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[schemaYAMLScalar](), reflect.TypeFor[schemaNodeScalar](), reflect.TypeFor[schemaTextScalar]()} {
		if _, err := generateJSONSchema(typ); err == nil || !strings.Contains(err.Error(), "override table") || !strings.Contains(err.Error(), typ.String()) {
			t.Errorf("%v: error = %v; want type name and override table guidance", typ, err)
		}
	}
	if _, err := generateJSONSchema(reflect.TypeFor[schemaPlain]()); err != nil {
		t.Error(err)
	}
	_, err := generateJSONSchema(reflect.TypeFor[struct {
		schemaPlain `yaml:",inline"`
		Value       bool `yaml:"value"`
	}]())
	if err == nil || !strings.Contains(err.Error(), "duplicate YAML key") {
		t.Errorf("duplicate inline key error = %v", err)
	}
}
