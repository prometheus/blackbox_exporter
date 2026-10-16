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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	// Make sure the well-known types are always registered in
	// protoregistry.GlobalFiles, so that descriptor sets and reflection
	// responses that omit them can still be resolved.
	_ "google.golang.org/protobuf/types/known/anypb"
	_ "google.golang.org/protobuf/types/known/durationpb"
	_ "google.golang.org/protobuf/types/known/emptypb"
	_ "google.golang.org/protobuf/types/known/fieldmaskpb"
	_ "google.golang.org/protobuf/types/known/structpb"
	_ "google.golang.org/protobuf/types/known/timestamppb"
	_ "google.golang.org/protobuf/types/known/wrapperspb"
)

// GRPCUnaryMethod configures the gRPC prober to call an arbitrary unary
// method instead of the standard health checking protocol.
type GRPCUnaryMethod struct {
	// Method is the fully-qualified method name, for example
	// "helloworld.Greeter/SayHello".
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	// Request is the request message encoded as protobuf JSON.
	Request string `yaml:"request,omitempty" json:"request,omitempty"`
	// DescriptorSetFile is the path to a binary FileDescriptorSet describing
	// the method. If empty, the descriptors are fetched using server reflection.
	DescriptorSetFile string `yaml:"descriptor_set_file,omitempty" json:"descriptor_set_file,omitempty"`
	// ValidStatusCodes lists the status codes that are considered a success.
	// Defaults to OK.
	ValidStatusCodes                []GRPCStatusCode `yaml:"valid_status_codes,omitempty" json:"valid_status_codes,omitempty"`
	FailIfResponseMatchesRegexp     []Regexp         `yaml:"fail_if_response_matches_regexp,omitempty" json:"fail_if_response_matches_regexp,omitempty"`
	FailIfResponseNotMatchesRegexp  []Regexp         `yaml:"fail_if_response_not_matches_regexp,omitempty" json:"fail_if_response_not_matches_regexp,omitempty"`
	FailIfResponseJSONMatchesCEL    *CELProgram      `yaml:"fail_if_response_json_matches_cel,omitempty" json:"fail_if_response_json_matches_cel,omitempty"`
	FailIfResponseJSONNotMatchesCEL *CELProgram      `yaml:"fail_if_response_json_not_matches_cel,omitempty" json:"fail_if_response_json_not_matches_cel,omitempty"`

	// files caches the parsed content of DescriptorSetFile.
	files *protoregistry.Files
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (m *GRPCUnaryMethod) UnmarshalYAML(unmarshal func(any) error) error {
	*m = GRPCUnaryMethod{}
	type plain GRPCUnaryMethod
	if err := unmarshal((*plain)(m)); err != nil {
		return err
	}
	return m.validate()
}

func (m *GRPCUnaryMethod) validate() error {
	service, method, err := m.ServiceAndMethod()
	if err != nil {
		return err
	}
	if m.Request != "" && !json.Valid([]byte(m.Request)) {
		return fmt.Errorf("request of gRPC method %q is not valid JSON", m.Method)
	}
	if m.DescriptorSetFile == "" {
		return nil
	}

	files, err := LoadDescriptorSetFile(m.DescriptorSetFile)
	if err != nil {
		return err
	}
	md, err := FindGRPCMethod(files, service, method)
	if err != nil {
		return fmt.Errorf("descriptor_set_file %q: %w", m.DescriptorSetFile, err)
	}
	if m.Request != "" {
		req := dynamicpb.NewMessage(md.Input())
		opts := protojson.UnmarshalOptions{Resolver: dynamicpb.NewTypes(files)}
		if err := opts.Unmarshal([]byte(m.Request), req); err != nil {
			return fmt.Errorf("request of gRPC method %q does not match %s: %w", m.Method, md.Input().FullName(), err)
		}
	}
	m.files = files
	return nil
}

// ServiceAndMethod splits Method into the fully-qualified service name and
// the method name. "pkg.Service/Method", "/pkg.Service/Method" and
// "pkg.Service.Method" are all accepted.
func (m *GRPCUnaryMethod) ServiceAndMethod() (service, method string, err error) {
	name := strings.TrimPrefix(m.Method, "/")
	if name == "" {
		return "", "", errors.New("method must be set for gRPC unary_method")
	}
	sep := strings.LastIndex(name, "/")
	if sep < 0 {
		sep = strings.LastIndex(name, ".")
	}
	if sep <= 0 || sep == len(name)-1 {
		return "", "", fmt.Errorf("gRPC method %q must have the form <package>.<service>/<method>", m.Method)
	}
	service, method = name[:sep], name[sep+1:]
	if !protoreflect.FullName(service).IsValid() || !protoreflect.Name(method).IsValid() {
		return "", "", fmt.Errorf("gRPC method %q must have the form <package>.<service>/<method>", m.Method)
	}
	return service, method, nil
}

// DescriptorFiles returns the descriptors loaded from DescriptorSetFile. The
// file is parsed once when the configuration is loaded; modules that were
// built without going through the YAML parser load it on every call.
func (m *GRPCUnaryMethod) DescriptorFiles() (*protoregistry.Files, error) {
	if m.files != nil {
		return m.files, nil
	}
	return LoadDescriptorSetFile(m.DescriptorSetFile)
}

// IsValidStatusCode reports whether code is accepted as a successful
// response. If no valid_status_codes are configured, only OK is accepted.
func (m *GRPCUnaryMethod) IsValidStatusCode(code codes.Code) bool {
	if len(m.ValidStatusCodes) == 0 {
		return code == codes.OK
	}
	for _, c := range m.ValidStatusCodes {
		if codes.Code(c) == code {
			return true
		}
	}
	return false
}

// LoadDescriptorSetFile reads a binary FileDescriptorSet, as produced by
// `protoc --descriptor_set_out` or `buf build -o`. Imports that are missing
// from the set are resolved against the well-known types compiled into the
// exporter.
func LoadDescriptorSetFile(path string) (*protoregistry.Files, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading descriptor_set_file: %w", err)
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(content, &set); err != nil {
		return nil, fmt.Errorf("error parsing descriptor_set_file %q: %w", path, err)
	}

	known := make(map[string]bool, len(set.File))
	for _, f := range set.File {
		known[f.GetName()] = true
	}
	for i := 0; i < len(set.File); i++ {
		for _, dep := range set.File[i].GetDependency() {
			if known[dep] {
				continue
			}
			fd, err := protoregistry.GlobalFiles.FindFileByPath(dep)
			if err != nil {
				return nil, fmt.Errorf("descriptor_set_file %q is missing import %q; build it with --include_imports", path, dep)
			}
			known[dep] = true
			set.File = append(set.File, protodesc.ToFileDescriptorProto(fd))
		}
	}

	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return nil, fmt.Errorf("error building descriptors from descriptor_set_file %q: %w", path, err)
	}
	return files, nil
}

// FindGRPCMethod looks up a unary method in files.
func FindGRPCMethod(files *protoregistry.Files, service, method string) (protoreflect.MethodDescriptor, error) {
	d, err := files.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return nil, fmt.Errorf("service %q not found", service)
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%q is not a service", service)
	}
	md := sd.Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return nil, fmt.Errorf("method %q not found in service %q", method, service)
	}
	if md.IsStreamingClient() || md.IsStreamingServer() {
		return nil, fmt.Errorf("method %q of service %q is a streaming method, only unary methods are supported", method, service)
	}
	return md, nil
}

// GRPCStatusCode is a gRPC status code that can be written in the
// configuration either by name (for example "NOT_FOUND") or by number.
type GRPCStatusCode codes.Code

// grpcStatusCodeNames are the canonical names of the status codes, as listed
// in https://grpc.github.io/grpc/core/md_doc_statuscodes.html.
var grpcStatusCodeNames = [...]string{
	"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED",
	"NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED",
	"FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED",
	"INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED",
}

// ParseGRPCStatusCode parses a status code name (case-insensitive) or number.
func ParseGRPCStatusCode(s string) (GRPCStatusCode, error) {
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		if n < uint64(len(grpcStatusCodeNames)) {
			return GRPCStatusCode(n), nil
		}
		return 0, fmt.Errorf("invalid gRPC status code %q", s)
	}
	upper := strings.ToUpper(s)
	for i, name := range grpcStatusCodeNames {
		if name == upper {
			return GRPCStatusCode(i), nil
		}
	}
	return 0, fmt.Errorf("invalid gRPC status code %q", s)
}

// String returns the canonical name of the status code.
func (c GRPCStatusCode) String() string {
	if int(c) < len(grpcStatusCodeNames) {
		return grpcStatusCodeNames[c]
	}
	return strconv.FormatUint(uint64(c), 10)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *GRPCStatusCode) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	code, err := ParseGRPCStatusCode(s)
	if err != nil {
		return err
	}
	*c = code
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (c GRPCStatusCode) MarshalYAML() (any, error) {
	return c.String(), nil
}

// MarshalJSON implements the json.Marshaler interface.
func (c GRPCStatusCode) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}
