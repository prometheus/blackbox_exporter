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

package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	reflectionalphapb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/prometheus/blackbox_exporter/config"
)

// testGreeterFileDescriptors describes the following service, split across
// two files so that dependency resolution is exercised:
//
//	// blackbox/test/common.proto
//	package blackbox.test;
//	message Greeting { string text = 1; int32 length = 2; }
//
//	// blackbox/test/greeter.proto
//	package blackbox.test;
//	import "blackbox/test/common.proto";
//	import "google/protobuf/timestamp.proto";
//	message HelloRequest { string name = 1; google.protobuf.Timestamp sent_at = 2; }
//	service Greeter {
//	  rpc SayHello(HelloRequest) returns (Greeting);
//	  rpc StreamHello(HelloRequest) returns (stream Greeting);
//	}
func testGreeterFileDescriptors() []*descriptorpb.FileDescriptorProto {
	field := func(name string, number int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name:   new(name),
			Number: new(number),
			Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			Type:   typ.Enum(),
		}
		if typeName != "" {
			f.TypeName = new(typeName)
		}
		return f
	}
	common := &descriptorpb.FileDescriptorProto{
		Name:    new("blackbox/test/common.proto"),
		Package: new("blackbox.test"),
		Syntax:  new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("Greeting"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("text", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
				field("length", 2, descriptorpb.FieldDescriptorProto_TYPE_INT32, ""),
			},
		}},
	}
	greeter := &descriptorpb.FileDescriptorProto{
		Name:       new("blackbox/test/greeter.proto"),
		Package:    new("blackbox.test"),
		Syntax:     new("proto3"),
		Dependency: []string{"blackbox/test/common.proto", "google/protobuf/timestamp.proto"},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("HelloRequest"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("name", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
				field("sent_at", 2, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".google.protobuf.Timestamp"),
			},
		}},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: new("Greeter"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{
					Name:       new("SayHello"),
					InputType:  new(".blackbox.test.HelloRequest"),
					OutputType: new(".blackbox.test.Greeting"),
				},
				{
					Name:            new("StreamHello"),
					InputType:       new(".blackbox.test.HelloRequest"),
					OutputType:      new(".blackbox.test.Greeting"),
					ServerStreaming: new(true),
				},
			},
		}},
	}
	return []*descriptorpb.FileDescriptorProto{common, greeter}
}

func testGreeterFiles(t *testing.T) *protoregistry.Files {
	t.Helper()
	set := &descriptorpb.FileDescriptorSet{
		File: append(testGreeterFileDescriptors(), protodesc.ToFileDescriptorProto(timestamppb.File_google_protobuf_timestamp_proto)),
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		t.Fatalf("Error building test descriptors: %s", err)
	}
	return files
}

// writeTestDescriptorSet writes the test service to a descriptor set file,
// leaving out google/protobuf/timestamp.proto like `protoc` does without
// --include_imports.
func writeTestDescriptorSet(t *testing.T) string {
	t.Helper()
	b, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: testGreeterFileDescriptors()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "greeter.protoset")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// registerTestGreeter registers a dynamic implementation of the test Greeter
// service. SayHello answers "Hello <name>", except for a few special names:
// "missing" returns NOT_FOUND, "slow" blocks until the deadline and "secret"
// requires an "authorization: Bearer token" metadata entry.
func registerTestGreeter(s *grpc.Server, files *protoregistry.Files) {
	desc, err := files.FindDescriptorByName("blackbox.test.Greeter")
	if err != nil {
		panic(err)
	}
	method := desc.(protoreflect.ServiceDescriptor).Methods().ByName("SayHello")

	handler := func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		req := dynamicpb.NewMessage(method.Input())
		if err := dec(req); err != nil {
			return nil, err
		}
		name := req.Get(method.Input().Fields().ByName("name")).String()
		switch name {
		case "missing":
			return nil, status.Error(codes.NotFound, "no such greeting")
		case "slow":
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		case "secret":
			md, _ := metadata.FromIncomingContext(ctx)
			if v := md.Get("authorization"); len(v) != 1 || v[0] != "Bearer token" {
				return nil, status.Error(codes.PermissionDenied, "missing token")
			}
		}
		resp := dynamicpb.NewMessage(method.Output())
		text := "Hello " + name
		resp.Set(method.Output().Fields().ByName("text"), protoreflect.ValueOfString(text))
		resp.Set(method.Output().Fields().ByName("length"), protoreflect.ValueOfInt32(int32(len(text))))
		return resp, nil
	}

	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "blackbox.test.Greeter",
		HandlerType: (*any)(nil),
		Methods:     []grpc.MethodDesc{{MethodName: "SayHello", Handler: handler}},
		Streams: []grpc.StreamDesc{{
			StreamName:    "StreamHello",
			ServerStreams: true,
			Handler: func(any, grpc.ServerStream) error {
				return status.Error(codes.Unimplemented, "not implemented")
			},
		}},
	}, struct{}{})
}

// minimalReflectionServer only ever returns the single file that was asked
// for, forcing the client to fetch dependencies one by one. It does not know
// about google/protobuf/timestamp.proto, so the client has to fall back to
// the well-known types compiled into the exporter.
type minimalReflectionServer struct {
	reflectionpb.UnimplementedServerReflectionServer
	files *protoregistry.Files
}

func (m *minimalReflectionServer) ServerReflectionInfo(stream grpc.BidiStreamingServer[reflectionpb.ServerReflectionRequest, reflectionpb.ServerReflectionResponse]) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var fd protoreflect.FileDescriptor
		switch r := req.MessageRequest.(type) {
		case *reflectionpb.ServerReflectionRequest_FileContainingSymbol:
			if d, err := m.files.FindDescriptorByName(protoreflect.FullName(r.FileContainingSymbol)); err == nil {
				fd = d.ParentFile()
			}
		case *reflectionpb.ServerReflectionRequest_FileByFilename:
			if r.FileByFilename != "google/protobuf/timestamp.proto" {
				fd, _ = m.files.FindFileByPath(r.FileByFilename)
			}
		}
		resp := &reflectionpb.ServerReflectionResponse{OriginalRequest: req}
		if fd == nil {
			resp.MessageResponse = &reflectionpb.ServerReflectionResponse_ErrorResponse{
				ErrorResponse: &reflectionpb.ErrorResponse{ErrorCode: int32(codes.NotFound), ErrorMessage: "not found"},
			}
		} else {
			b, err := proto.Marshal(protodesc.ToFileDescriptorProto(fd))
			if err != nil {
				return err
			}
			resp.MessageResponse = &reflectionpb.ServerReflectionResponse_FileDescriptorResponse{
				FileDescriptorResponse: &reflectionpb.FileDescriptorResponse{FileDescriptorProto: [][]byte{b}},
			}
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

type testReflectionMode int

const (
	reflectionV1 testReflectionMode = iota
	reflectionV1Alpha
	reflectionMinimal
	reflectionNone
)

// startTestGreeterServer starts the test Greeter service on a random IPv4
// loopback port and returns the probe target.
func startTestGreeterServer(t *testing.T, mode testReflectionMode, opts ...grpc.ServerOption) string {
	t.Helper()
	files := testGreeterFiles(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	s := grpc.NewServer(opts...)
	registerTestGreeter(s, files)

	reflectionOpts := reflection.ServerOptions{Services: s, DescriptorResolver: files}
	switch mode {
	case reflectionV1:
		reflectionpb.RegisterServerReflectionServer(s, reflection.NewServerV1(reflectionOpts))
	case reflectionV1Alpha:
		reflectionalphapb.RegisterServerReflectionServer(s, reflection.NewServer(reflectionOpts))
	case reflectionMinimal:
		reflectionpb.RegisterServerReflectionServer(s, &minimalReflectionServer{files: files})
	case reflectionNone:
	}

	go func() {
		_ = s.Serve(ln)
	}()
	t.Cleanup(s.Stop)
	return ln.Addr().String()
}

func TestGRPCUnaryMethod(t *testing.T) {
	descriptorSetFile := writeTestDescriptorSet(t)

	tests := []struct {
		name          string
		reflection    testReflectionMode
		probe         config.GRPCProbe
		method        config.GRPCUnaryMethod
		timeout       time.Duration
		wantSuccess   bool
		wantResults   map[string]float64
		wantAbsent    []string
		wantDurations []string
	}{
		{
			name:       "reflection v1 with matching regexp",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:                         "blackbox.test.Greeter/SayHello",
				Request:                        `{"name": "blackbox", "sentAt": "2024-01-01T00:00:00Z"}`,
				FailIfResponseNotMatchesRegexp: []config.Regexp{config.MustNewRegexp(`"text":"Hello blackbox"`)},
			},
			wantSuccess: true,
			wantResults: map[string]float64{
				"probe_grpc_status_code":            0,
				"probe_grpc_reflection_status_code": 0,
				"probe_grpc_response_size_bytes":    18,
				"probe_failed_due_to_regex":         0,
				"probe_grpc_ssl":                    0,
			},
			wantAbsent:    []string{"probe_grpc_healthcheck_response", "probe_failed_due_to_cel"},
			wantDurations: []string{"resolve", "reflection", "check"},
		},
		{
			name:       "method name with dot separator and leading slash",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:  "/blackbox.test.Greeter.SayHello",
				Request: `{"name": "blackbox"}`,
			},
			wantSuccess: true,
		},
		{
			name:       "empty request",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:                         "blackbox.test.Greeter/SayHello",
				FailIfResponseNotMatchesRegexp: []config.Regexp{config.MustNewRegexp(`^\{"text":"Hello ","length":6\}$`)},
			},
			wantSuccess: true,
		},
		{
			name:       "response not matching regexp",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:                         "blackbox.test.Greeter/SayHello",
				Request:                        `{"name": "blackbox"}`,
				FailIfResponseNotMatchesRegexp: []config.Regexp{config.MustNewRegexp(`Goodbye`)},
			},
			wantResults: map[string]float64{"probe_failed_due_to_regex": 1},
		},
		{
			name:       "response matching forbidden regexp",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:                      "blackbox.test.Greeter/SayHello",
				Request:                     `{"name": "blackbox"}`,
				FailIfResponseMatchesRegexp: []config.Regexp{config.MustNewRegexp(`blackbox`)},
			},
			wantResults: map[string]float64{"probe_failed_due_to_regex": 1},
		},
		{
			name:       "response matching CEL",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:                          "blackbox.test.Greeter/SayHello",
				Request:                         `{"name": "blackbox"}`,
				FailIfResponseJSONNotMatchesCEL: celProgram(`body.text == "Hello blackbox" && body.length == 14`),
				FailIfResponseJSONMatchesCEL:    celProgram(`body.text.startsWith("Goodbye")`),
			},
			wantSuccess: true,
			wantResults: map[string]float64{"probe_failed_due_to_cel": 0},
			wantAbsent:  []string{"probe_failed_due_to_regex"},
		},
		{
			name:       "response not matching CEL",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:                          "blackbox.test.Greeter/SayHello",
				Request:                         `{"name": "blackbox"}`,
				FailIfResponseJSONNotMatchesCEL: celProgram(`body.length > 100`),
			},
			wantResults: map[string]float64{"probe_failed_due_to_cel": 1},
		},
		{
			name:       "error status is a failure by default",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:  "blackbox.test.Greeter/SayHello",
				Request: `{"name": "missing"}`,
			},
			wantResults: map[string]float64{"probe_grpc_status_code": float64(codes.NotFound)},
			wantAbsent:  []string{"probe_grpc_response_size_bytes"},
		},
		{
			name:       "error status accepted by valid_status_codes",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:           "blackbox.test.Greeter/SayHello",
				Request:          `{"name": "missing"}`,
				ValidStatusCodes: []config.GRPCStatusCode{config.GRPCStatusCode(codes.OK), config.GRPCStatusCode(codes.NotFound)},
				// Response matchers are skipped when there is no response.
				FailIfResponseNotMatchesRegexp: []config.Regexp{config.MustNewRegexp(`Hello`)},
			},
			wantSuccess: true,
			wantResults: map[string]float64{"probe_grpc_status_code": float64(codes.NotFound)},
			wantAbsent:  []string{"probe_failed_due_to_regex"},
		},
		{
			name:       "OK not accepted by valid_status_codes",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:           "blackbox.test.Greeter/SayHello",
				Request:          `{"name": "blackbox"}`,
				ValidStatusCodes: []config.GRPCStatusCode{config.GRPCStatusCode(codes.NotFound)},
			},
			wantResults: map[string]float64{"probe_grpc_status_code": 0},
		},
		{
			name:       "metadata is sent with the request",
			reflection: reflectionV1,
			probe:      config.GRPCProbe{Metadata: metadata.Pairs("authorization", "Bearer token")},
			method: config.GRPCUnaryMethod{
				Method:  "blackbox.test.Greeter/SayHello",
				Request: `{"name": "secret"}`,
			},
			wantSuccess: true,
			wantResults: map[string]float64{"probe_grpc_status_code": 0},
		},
		{
			name:       "missing metadata",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:  "blackbox.test.Greeter/SayHello",
				Request: `{"name": "secret"}`,
			},
			wantResults: map[string]float64{"probe_grpc_status_code": float64(codes.PermissionDenied)},
		},
		{
			name:       "timeout",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:  "blackbox.test.Greeter/SayHello",
				Request: `{"name": "slow"}`,
			},
			timeout:     500 * time.Millisecond,
			wantResults: map[string]float64{"probe_grpc_status_code": float64(codes.DeadlineExceeded)},
		},
		{
			name:       "unknown method",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method: "blackbox.test.Greeter/SayGoodbye",
			},
			wantAbsent: []string{"probe_grpc_status_code"},
		},
		{
			name:       "unknown service",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method: "blackbox.test.Unknown/SayHello",
			},
			wantResults: map[string]float64{"probe_grpc_reflection_status_code": float64(codes.NotFound)},
			wantAbsent:  []string{"probe_grpc_status_code"},
		},
		{
			name:       "streaming method",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method: "blackbox.test.Greeter/StreamHello",
			},
			wantAbsent: []string{"probe_grpc_status_code"},
		},
		{
			name:       "request does not match the input type",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:  "blackbox.test.Greeter/SayHello",
				Request: `{"nickname": "blackbox"}`,
			},
			wantAbsent: []string{"probe_grpc_status_code"},
		},
		{
			name:       "reflection v1alpha",
			reflection: reflectionV1Alpha,
			method: config.GRPCUnaryMethod{
				Method:                         "blackbox.test.Greeter/SayHello",
				Request:                        `{"name": "blackbox"}`,
				FailIfResponseNotMatchesRegexp: []config.Regexp{config.MustNewRegexp(`Hello blackbox`)},
			},
			wantSuccess: true,
			wantResults: map[string]float64{"probe_grpc_reflection_status_code": 0},
		},
		{
			name:       "reflection server returning one file at a time",
			reflection: reflectionMinimal,
			method: config.GRPCUnaryMethod{
				Method:  "blackbox.test.Greeter/SayHello",
				Request: `{"name": "blackbox", "sentAt": "2024-01-01T00:00:00Z"}`,
			},
			wantSuccess: true,
		},
		{
			name:       "reflection not available",
			reflection: reflectionNone,
			method: config.GRPCUnaryMethod{
				Method:  "blackbox.test.Greeter/SayHello",
				Request: `{"name": "blackbox"}`,
			},
			wantResults: map[string]float64{"probe_grpc_reflection_status_code": float64(codes.Unimplemented)},
			wantAbsent:  []string{"probe_grpc_status_code"},
		},
		{
			name:       "descriptor set file without reflection",
			reflection: reflectionNone,
			method: config.GRPCUnaryMethod{
				Method:                         "blackbox.test.Greeter/SayHello",
				Request:                        `{"name": "blackbox", "sentAt": "2024-01-01T00:00:00Z"}`,
				DescriptorSetFile:              descriptorSetFile,
				FailIfResponseNotMatchesRegexp: []config.Regexp{config.MustNewRegexp(`Hello blackbox`)},
			},
			wantSuccess:   true,
			wantResults:   map[string]float64{"probe_grpc_status_code": 0},
			wantAbsent:    []string{"probe_grpc_reflection_status_code"},
			wantDurations: []string{"resolve", "check"},
		},
		{
			name:       "descriptor set file not found",
			reflection: reflectionV1,
			method: config.GRPCUnaryMethod{
				Method:            "blackbox.test.Greeter/SayHello",
				DescriptorSetFile: filepath.Join(t.TempDir(), "missing.protoset"),
			},
			wantAbsent: []string{"probe_grpc_status_code"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := startTestGreeterServer(t, test.reflection)

			timeout := test.timeout
			if timeout == 0 {
				timeout = 10 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			module := config.Module{Timeout: timeout, GRPC: test.probe}
			module.GRPC.PreferredIPProtocol = "ip4"
			module.GRPC.UnaryMethod = &test.method

			registry := prometheus.NewRegistry()
			if got := ProbeGRPC(ctx, target, module, registry, promslog.NewNopLogger()); got != test.wantSuccess {
				t.Fatalf("ProbeGRPC() = %v, want %v", got, test.wantSuccess)
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			checkRegistryResults(test.wantResults, mfs, t)
			checkAbsentMetrics(test.wantAbsent, mfs, t)
			for _, phase := range test.wantDurations {
				if _, ok := getMetricWithLabels(mfs, "probe_grpc_duration_seconds", map[string]string{"phase": phase}); !ok {
					t.Errorf("probe_grpc_duration_seconds{phase=%q} not found", phase)
				}
			}
		})
	}
}

func TestGRPCUnaryMethodTLS(t *testing.T) {
	certExpiry := time.Now().AddDate(0, 0, 1)
	certTmpl := generateCertificateTemplate(certExpiry, true)
	certTmpl.IsCA = true
	_, certPem, key := generateSelfSignedCertificate(certTmpl)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatalf("Error decoding TLS key pair: %s", err)
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	target := startTestGreeterServer(t, reflectionV1, grpc.Creds(credentials.NewTLS(serverTLS)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	module := config.Module{
		Timeout: 10 * time.Second,
		GRPC: config.GRPCProbe{
			TLS:                 true,
			TLSConfig:           pconfig.TLSConfig{InsecureSkipVerify: true},
			PreferredIPProtocol: "ip4",
			UnaryMethod: &config.GRPCUnaryMethod{
				Method:                         "blackbox.test.Greeter/SayHello",
				Request:                        `{"name": "tls"}`,
				FailIfResponseNotMatchesRegexp: []config.Regexp{config.MustNewRegexp(`Hello tls`)},
			},
		},
	}
	if !ProbeGRPC(ctx, target, module, registry, promslog.NewNopLogger()) {
		t.Fatal("gRPC unary method probe over TLS failed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	checkRegistryResults(map[string]float64{
		"probe_grpc_ssl":                    1,
		"probe_grpc_status_code":            0,
		"probe_ssl_earliest_cert_expiry":    float64(certExpiry.Unix()),
		"probe_grpc_reflection_status_code": 0,
	}, mfs, t)
}

func celProgram(expr string) *config.CELProgram {
	p := config.MustNewCELProgram(expr)
	return &p
}
