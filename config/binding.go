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
	"bytes"
	"reflect"

	"github.com/bytedance/go-tagexpr/v2/binding"
	"github.com/prometheus/common/config"
	"gopkg.in/yaml.v3"
)

func InitializeBinding() {
	binding.MustRegTypeUnmarshal(reflect.TypeOf(Regexp{}), func(v string, emptyAsZero bool) (reflect.Value, error) {
		if v == "" && emptyAsZero {
			return reflect.ValueOf(Regexp{}), nil
		}

		t, err := NewRegexp(v)
		if err != nil {
			return reflect.ValueOf(Regexp{}), err
		}

		return reflect.ValueOf(t), nil
	})

	binding.MustRegTypeUnmarshal(reflect.TypeOf(HeaderMatch{}), func(v string, emptyAsZero bool) (reflect.Value, error) {
		if v == "" && emptyAsZero {
			return reflect.ValueOf(HeaderMatch{}), nil
		}

		var c = &HeaderMatch{}

		decoder := yaml.NewDecoder(bytes.NewBufferString(v))
		decoder.KnownFields(true)

		if err := decoder.Decode(c); err != nil {
			return reflect.ValueOf(HeaderMatch{}), err
		}

		if err := c.Validate(); err != nil {
			return reflect.ValueOf(HeaderMatch{}), err
		}

		return reflect.ValueOf(*c), nil
	})

	binding.MustRegTypeUnmarshal(reflect.TypeOf(config.HTTPClientConfig{}), binderYamlDecoder(config.HTTPClientConfig{}))
	binding.MustRegTypeUnmarshal(reflect.TypeOf(config.TLSConfig{}), binderYamlDecoder(config.TLSConfig{}))
	binding.MustRegTypeUnmarshal(reflect.TypeOf(DNSRRValidator{}), binderYamlDecoder(DNSRRValidator{}))
}

func binderYamlDecoder[T any](s T) func(v string, emptyAsZero bool) (reflect.Value, error) {
	return func(v string, emptyAsZero bool) (reflect.Value, error) {
		if v == "" && emptyAsZero {
			return reflect.ValueOf(s), nil
		}

		var c = &s

		decoder := yaml.NewDecoder(bytes.NewBufferString(v))
		decoder.KnownFields(true)

		if err := decoder.Decode(c); err != nil {
			return reflect.ValueOf(s), err
		}

		return reflect.ValueOf(*c), nil
	}
}
