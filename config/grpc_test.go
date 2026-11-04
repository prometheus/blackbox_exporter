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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestGRPCUnaryMethodServiceAndMethod(t *testing.T) {
	tests := []struct {
		method      string
		wantService string
		wantMethod  string
		wantErr     bool
	}{
		{method: "helloworld.Greeter/SayHello", wantService: "helloworld.Greeter", wantMethod: "SayHello"},
		{method: "/helloworld.Greeter/SayHello", wantService: "helloworld.Greeter", wantMethod: "SayHello"},
		{method: "helloworld.Greeter.SayHello", wantService: "helloworld.Greeter", wantMethod: "SayHello"},
		{method: "Greeter/SayHello", wantService: "Greeter", wantMethod: "SayHello"},
		{method: "", wantErr: true},
		{method: "SayHello", wantErr: true},
		{method: "helloworld.Greeter/", wantErr: true},
		{method: "/SayHello", wantErr: true},
		{method: "hello world.Greeter/SayHello", wantErr: true},
		{method: "helloworld.Greeter/Say.Hello", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			m := GRPCUnaryMethod{Method: test.method}
			service, method, err := m.ServiceAndMethod()
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got service=%q method=%q", service, method)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if service != test.wantService || method != test.wantMethod {
				t.Fatalf("got (%q, %q), want (%q, %q)", service, method, test.wantService, test.wantMethod)
			}
		})
	}
}

func TestParseGRPCStatusCode(t *testing.T) {
	tests := []struct {
		input   string
		want    codes.Code
		wantErr bool
	}{
		{input: "OK", want: codes.OK},
		{input: "not_found", want: codes.NotFound},
		{input: "Unauthenticated", want: codes.Unauthenticated},
		{input: "0", want: codes.OK},
		{input: "14", want: codes.Unavailable},
		{input: "16", want: codes.Unauthenticated},
		{input: "17", wantErr: true},
		{input: "-1", wantErr: true},
		{input: "NotFound", wantErr: true},
		{input: "", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := ParseGRPCStatusCode(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if codes.Code(got) != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestGRPCUnaryMethodIsValidStatusCode(t *testing.T) {
	var m GRPCUnaryMethod
	if !m.IsValidStatusCode(codes.OK) || m.IsValidStatusCode(codes.NotFound) {
		t.Fatal("only OK should be valid by default")
	}
	m.ValidStatusCodes = []GRPCStatusCode{GRPCStatusCode(codes.NotFound)}
	if m.IsValidStatusCode(codes.OK) || !m.IsValidStatusCode(codes.NotFound) {
		t.Fatal("only NOT_FOUND should be valid")
	}
}

func TestGRPCUnaryMethodYAMLRoundTrip(t *testing.T) {
	input := `method: helloworld.Greeter/SayHello
request: '{"name": "blackbox"}'
valid_status_codes:
    - OK
    - NOT_FOUND
fail_if_response_not_matches_regexp:
    - Hello
fail_if_response_json_not_matches_cel: body.message != ""
`
	var m GRPCUnaryMethod
	if err := yaml.Unmarshal([]byte(input), &m); err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != input {
		t.Fatalf("round trip mismatch:\n got: %s\nwant: %s", out, input)
	}
}

// writeDescriptorSet writes a descriptor set for:
//
//	package helloworld;
//	import "google/protobuf/empty.proto";
//	message HelloRequest { string name = 1; }
//	service Greeter {
//	  rpc SayHello(HelloRequest) returns (google.protobuf.Empty);
//	  rpc Watch(HelloRequest) returns (stream google.protobuf.Empty);
//	}
//
// The import is not included, as with `protoc` without --include_imports.
func writeDescriptorSet(t *testing.T) string {
	t.Helper()
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:       new("helloworld.proto"),
		Package:    new("helloworld"),
		Syntax:     new("proto3"),
		Dependency: []string{"google/protobuf/empty.proto"},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("HelloRequest"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:   new("name"),
				Number: new(int32(1)),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			}},
		}},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: new("Greeter"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{
					Name:       new("SayHello"),
					InputType:  new(".helloworld.HelloRequest"),
					OutputType: new(".google.protobuf.Empty"),
				},
				{
					Name:            new("Watch"),
					InputType:       new(".helloworld.HelloRequest"),
					OutputType:      new(".google.protobuf.Empty"),
					ServerStreaming: new(true),
				},
			},
		}},
	}}}
	b, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helloworld.protoset")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGRPCUnaryMethodDescriptorSetFile(t *testing.T) {
	descriptorSet := writeDescriptorSet(t)
	invalidFile := filepath.Join(t.TempDir(), "invalid.protoset")
	if err := os.WriteFile(invalidFile, []byte("not a descriptor set"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		method  string
		request string
		file    string
		wantErr string
	}{
		{name: "valid", method: "helloworld.Greeter/SayHello", request: `{"name": "blackbox"}`, file: descriptorSet},
		{name: "valid without request", method: "helloworld.Greeter/SayHello", file: descriptorSet},
		{name: "unknown service", method: "helloworld.Unknown/SayHello", file: descriptorSet, wantErr: `service "helloworld.Unknown" not found`},
		{name: "unknown method", method: "helloworld.Greeter/SayGoodbye", file: descriptorSet, wantErr: `method "SayGoodbye" not found in service "helloworld.Greeter"`},
		{name: "streaming method", method: "helloworld.Greeter/Watch", file: descriptorSet, wantErr: "only unary methods are supported"},
		{name: "request with unknown field", method: "helloworld.Greeter/SayHello", request: `{"nickname": "blackbox"}`, file: descriptorSet, wantErr: "does not match helloworld.HelloRequest"},
		{name: "missing file", method: "helloworld.Greeter/SayHello", file: filepath.Join(t.TempDir(), "missing"), wantErr: "error reading descriptor_set_file"},
		{name: "invalid file", method: "helloworld.Greeter/SayHello", file: invalidFile, wantErr: "error parsing descriptor_set_file"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, err := yaml.Marshal(map[string]string{
				"method":              test.method,
				"request":             test.request,
				"descriptor_set_file": test.file,
			})
			if err != nil {
				t.Fatal(err)
			}
			var m GRPCUnaryMethod
			err = yaml.Unmarshal(input, &m)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("got error %v, want error containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.files == nil {
				t.Fatal("descriptors were not cached while loading the configuration")
			}
			files, err := m.DescriptorFiles()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := FindGRPCMethod(files, "helloworld.Greeter", "SayHello"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoadDescriptorSetFileMissingImport(t *testing.T) {
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:       new("a.proto"),
		Package:    new("a"),
		Dependency: []string{"b.proto"},
	}}}
	b, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.protoset")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadDescriptorSetFile(path)
	if err == nil || !strings.Contains(err.Error(), `missing import "b.proto"`) {
		t.Fatalf("got error %v, want missing import error", err)
	}
}
