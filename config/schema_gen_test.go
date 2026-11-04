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
	"encoding"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/units"
	common "github.com/prometheus/common/config"
	"go.yaml.in/yaml/v3"
)

//go:generate go test -run ^TestJSONSchemaUpToDate$ -update .

type schemaObject = map[string]any

type schemaGenerator struct {
	definitions map[string]schemaObject
	names       map[string]reflect.Type
	overrides   map[reflect.Type]schemaObject
	active      map[reflect.Type]bool
}

// generateJSONSchema lives in a test file to avoid a public API or new dependencies.
// TestJSONSchemaUpToDate regenerates the schema when passed -update.
func generateJSONSchema(root reflect.Type) ([]byte, error) {
	versions := make([]string, 0, len(common.TLSVersions))
	for name := range common.TLSVersions {
		versions = append(versions, name)
	}
	slices.Sort(versions)
	// units.ParseBase2Bytes accepts signed quantities with B, KB or KiB units through EB/EiB, or zero.
	number := `([0-9]+(\.[0-9]*)?|\.[0-9]+)`
	sizePattern := "^[+-]?(0|(" + number + "([KMGTPE]iB|B))+|(" + number + "([KMGTPE]?B))+)$"
	// time.ParseDuration accepts signed sequences of decimal numbers with units, or zero.
	durationPattern := "^[+-]?(0|(" + number + "(ns|us|µs|μs|ms|s|m|h))+)$"
	g := schemaGenerator{
		definitions: map[string]schemaObject{},
		names:       map[string]reflect.Type{},
		active:      map[reflect.Type]bool{},
		overrides: map[reflect.Type]schemaObject{
			reflect.TypeFor[Regexp]():            stringSchema(),
			reflect.TypeFor[CELProgram]():        stringSchema(),
			reflect.TypeFor[common.Secret]():     stringSchema(),
			reflect.TypeFor[common.URL]():        stringSchema(),
			reflect.TypeFor[common.TLSVersion](): {"type": "string", "enum": versions},
			reflect.TypeFor[time.Duration]():     {"type": "string", "pattern": durationPattern},
			reflect.TypeFor[units.Base2Bytes](): {"anyOf": []schemaObject{
				{"type": "string", "pattern": sizePattern},
				{"const": 0},
			}},
		},
	}
	root = schemaType(root)
	var doc schemaObject
	var err error
	if root.Kind() == reflect.Struct && g.overrides[root] == nil {
		doc, err = g.object(root, map[reflect.Type]bool{})
	} else {
		doc, err = g.schema(root)
	}
	if err != nil {
		return nil, err
	}
	doc["$schema"] = "http://json-schema.org/draft-07/schema#"
	doc["title"] = "Blackbox exporter configuration"
	doc["definitions"] = g.definitions
	data, err := json.MarshalIndent(doc, "", "  ") // encoding/json sorts object keys.
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// stringSchema matches string fields: yaml v3 decodes any non-null scalar into a string.
func stringSchema() schemaObject {
	return schemaObject{"type": []string{"string", "number", "boolean"}}
}

func schemaType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func checkSchemaScalar(t reflect.Type) error {
	tagged := false
	if t.Kind() == reflect.Struct {
		for f := range t.Fields() {
			if tag, ok := f.Tag.Lookup("yaml"); f.IsExported() && ok && tag != "-" {
				tagged = true
			}
		}
	}
	if t.Name() != "" && !tagged {
		for _, candidate := range []reflect.Type{t, reflect.PointerTo(t)} {
			if candidate.Implements(reflect.TypeFor[interface{ UnmarshalYAML(func(any) error) error }]()) ||
				candidate.Implements(reflect.TypeFor[yaml.Unmarshaler]()) ||
				candidate.Implements(reflect.TypeFor[encoding.TextUnmarshaler]()) {
				return fmt.Errorf("custom scalar %v: add it to the override table", t)
			}
		}
	}
	return nil
}

func (g *schemaGenerator) schema(t reflect.Type) (schemaObject, error) {
	t = schemaType(t)
	if override, ok := g.overrides[t]; ok {
		return override, nil
	}
	if err := checkSchemaScalar(t); err != nil {
		return nil, err
	}
	if t.Kind() != reflect.Struct {
		if g.active[t] {
			return nil, fmt.Errorf("recursive non-struct type %v", t)
		}
		g.active[t] = true
		defer delete(g.active, t)
	}
	switch t.Kind() {
	case reflect.Struct:
		if t.Name() == "" {
			return g.object(t, map[reflect.Type]bool{})
		}
		name := t.Name()
		switch t.PkgPath() {
		case reflect.TypeFor[Config]().PkgPath():
		case "github.com/prometheus/common/config":
			name = "common." + name
		default:
			name = path.Base(t.PkgPath()) + "." + name
		}
		if previous, ok := g.names[name]; ok {
			if previous != t {
				return nil, fmt.Errorf("definition %q collides for %v and %v", name, previous, t)
			}
		} else {
			g.names[name] = t // Reserve before descending to allow recursive references.
			object, err := g.object(t, map[reflect.Type]bool{})
			if err != nil {
				return nil, err
			}
			g.definitions[name] = object
		}
		return schemaObject{"$ref": "#/definitions/" + name}, nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, fmt.Errorf("unsupported map key in %v", t)
		}
		if t.Elem() == reflect.TypeFor[any]() {
			return schemaObject{"type": []string{"object", "null"}, "additionalProperties": schemaObject{}}, nil
		}
		value, err := g.schema(t.Elem())
		return schemaObject{"type": []string{"object", "null"}, "additionalProperties": value}, err
	case reflect.Slice, reflect.Array:
		items, err := g.schema(t.Elem())
		return schemaObject{"type": []string{"array", "null"}, "items": items}, err
	case reflect.String:
		return stringSchema(), nil
	case reflect.Bool:
		return schemaObject{"type": "boolean"}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return schemaObject{"type": "integer"}, nil
	case reflect.Float32, reflect.Float64:
		return schemaObject{"type": "number"}, nil
	}
	return nil, fmt.Errorf("unsupported type %v (%v)", t, t.Kind())
}

func (g *schemaGenerator) object(t reflect.Type, inline map[reflect.Type]bool) (schemaObject, error) {
	if err := checkSchemaScalar(t); err != nil {
		return nil, err
	}
	if inline[t] {
		return nil, fmt.Errorf("recursive inline type %v", t)
	}
	inline[t] = true
	defer delete(inline, t)
	properties := schemaObject{}
	object := schemaObject{"type": []string{"object", "null"}, "properties": properties, "additionalProperties": false}
	for f := range t.Fields() {
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		tag := strings.Split(f.Tag.Get("yaml"), ",")
		if tag[0] == "-" {
			continue
		}
		if slices.Contains(tag[1:], "inline") {
			ft := schemaType(f.Type)
			var nested schemaObject
			var err error
			if ft.Kind() == reflect.Struct && g.overrides[ft] == nil {
				nested, err = g.object(ft, inline)
			} else {
				nested, err = g.schema(ft)
			}
			if err != nil {
				return nil, err
			}
			if _, ok := nested["additionalProperties"]; !ok {
				return nil, fmt.Errorf("unsupported or recursive inline type %v", f.Type)
			}
			if extra := nested["additionalProperties"]; extra != false {
				if object["additionalProperties"] != false {
					return nil, fmt.Errorf("multiple inline maps in %v", t)
				}
				object["additionalProperties"] = extra
			}
			if fields, ok := nested["properties"].(schemaObject); ok {
				for name, field := range fields {
					if _, exists := properties[name]; exists {
						return nil, fmt.Errorf("duplicate YAML key %q in %v", name, t)
					}
					properties[name] = field
				}
			}
			continue
		}
		name := tag[0]
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		if _, exists := properties[name]; exists {
			return nil, fmt.Errorf("duplicate YAML key %q in %v", name, t)
		}
		field, err := g.schema(f.Type)
		if err != nil {
			return nil, fmt.Errorf("%v.%s: %w", t, f.Name, err)
		}
		properties[name] = field
	}
	return object, nil
}
