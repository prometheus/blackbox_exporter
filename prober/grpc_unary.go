// Copyright 2026 The Prometheus Authors
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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	rpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/prometheus/blackbox_exporter/config"
)

// maxReflectionFiles bounds the number of file descriptors a probe fetches
// from the target, so a misbehaving server cannot keep a probe busy until
// its timeout.
const maxReflectionFiles = 128

// unaryResult describes the outcome of a unary gRPC call.
type unaryResult struct {
	reflectionDuration time.Duration
	statusCode         codes.Code
	peer               *peer.Peer
	// matched is nil when the module does not set expected_response.
	matched *bool
}

// probeUnaryMethod looks up the method on the target through the gRPC server
// reflection service, sends the configured request and optionally compares the
// response with the configured expectation.
func probeUnaryMethod(ctx context.Context, conn *grpc.ClientConn, probe config.GRPCProbe, logger *slog.Logger) (unaryResult, error) {
	var res unaryResult

	serviceName, methodName, err := config.SplitGRPCMethod(probe.Method)
	if err != nil {
		return res, err
	}

	ctx = metadata.NewOutgoingContext(ctx, probe.Metadata)

	reflectionStart := time.Now()
	method, err := lookupMethod(ctx, conn, serviceName, methodName)
	res.reflectionDuration = time.Since(reflectionStart)
	if err != nil {
		if s, ok := status.FromError(err); ok {
			res.statusCode = s.Code()
		}
		return res, fmt.Errorf("reflection lookup of %s/%s failed: %w", serviceName, methodName, err)
	}
	if method.IsStreamingClient() || method.IsStreamingServer() {
		return res, fmt.Errorf("method %s/%s is a streaming method, only unary methods are supported", serviceName, methodName)
	}

	request := dynamicpb.NewMessage(method.Input())
	if err := prototext.Unmarshal([]byte(probe.Request), request); err != nil {
		return res, fmt.Errorf("cannot parse request as %s: %w", method.Input().FullName(), err)
	}
	var expected *dynamicpb.Message
	if probe.ExpectedResponse != "" {
		expected = dynamicpb.NewMessage(method.Output())
		if err := prototext.Unmarshal([]byte(probe.ExpectedResponse), expected); err != nil {
			return res, fmt.Errorf("cannot parse expected_response as %s: %w", method.Output().FullName(), err)
		}
	}

	response := dynamicpb.NewMessage(method.Output())
	res.peer = new(peer.Peer)
	err = conn.Invoke(ctx, "/"+serviceName+"/"+methodName, request, response, grpc.Peer(res.peer))
	if err != nil {
		s, _ := status.FromError(err)
		res.statusCode = s.Code()
		return res, err
	}

	if expected != nil {
		matched := proto.Equal(expected, response)
		res.matched = &matched
		if !matched {
			logger.Debug("gRPC response differs from expected_response", "response", prototext.MarshalOptions{}.Format(response))
			return res, errors.New("gRPC response does not match expected_response")
		}
	}
	return res, nil
}

// lookupMethod resolves a service method through the server reflection API of
// the target.
func lookupMethod(ctx context.Context, conn *grpc.ClientConn, serviceName, methodName string) (protoreflect.MethodDescriptor, error) {
	stream, err := rpb.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CloseSend()

	r := &reflectionResolver{
		stream: stream,
		protos: map[string]*descriptorpb.FileDescriptorProto{},
		files:  &protoregistry.Files{},
	}

	err = r.fetch(&rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: serviceName},
	})
	if err != nil {
		return nil, err
	}
	// The file that declares the service is the one that holds the symbol.
	var root string
	for name, fdp := range r.protos {
		for _, svc := range fdp.GetService() {
			if fdp.GetPackage() != "" && fdp.GetPackage()+"."+svc.GetName() == serviceName || fdp.GetPackage() == "" && svc.GetName() == serviceName {
				root = name
			}
		}
	}
	if root == "" {
		return nil, fmt.Errorf("service %s not found in the reflection response", serviceName)
	}
	if err := r.build(root, map[string]bool{}); err != nil {
		return nil, err
	}

	desc, err := r.files.FindDescriptorByName(protoreflect.FullName(serviceName))
	if err != nil {
		return nil, err
	}
	svc, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is not a service", serviceName)
	}
	method := svc.Methods().ByName(protoreflect.Name(methodName))
	if method == nil {
		return nil, fmt.Errorf("service %s has no method %s", serviceName, methodName)
	}
	return method, nil
}

// reflectionResolver collects file descriptors over one reflection stream and
// turns them into resolved descriptors.
type reflectionResolver struct {
	stream  rpb.ServerReflection_ServerReflectionInfoClient
	protos  map[string]*descriptorpb.FileDescriptorProto
	files   *protoregistry.Files
	fetched int
}

// fetch sends one reflection request and stores the file descriptors of the
// answer.
func (r *reflectionResolver) fetch(req *rpb.ServerReflectionRequest) error {
	r.fetched++
	if r.fetched > maxReflectionFiles {
		return fmt.Errorf("more than %d reflection requests were needed", maxReflectionFiles)
	}
	if err := r.stream.Send(req); err != nil {
		return err
	}
	resp, err := r.stream.Recv()
	if err != nil {
		return err
	}
	if e := resp.GetErrorResponse(); e != nil {
		return status.Error(codes.Code(e.GetErrorCode()), e.GetErrorMessage())
	}
	fdr := resp.GetFileDescriptorResponse()
	if fdr == nil {
		return errors.New("unexpected reflection response")
	}
	for _, raw := range fdr.GetFileDescriptorProto() {
		fdp := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(raw, fdp); err != nil {
			return err
		}
		r.protos[fdp.GetName()] = fdp
	}
	return nil
}

// build registers the named file after all of its dependencies, asking the
// server for the files it did not send along.
func (r *reflectionResolver) build(name string, visiting map[string]bool) error {
	if _, err := r.files.FindFileByPath(name); err == nil {
		return nil
	}
	if visiting[name] {
		return fmt.Errorf("import cycle through %s", name)
	}
	visiting[name] = true
	defer delete(visiting, name)

	fdp, ok := r.protos[name]
	if !ok {
		if err := r.fetch(&rpb.ServerReflectionRequest{
			MessageRequest: &rpb.ServerReflectionRequest_FileByFilename{FileByFilename: name},
		}); err != nil {
			return err
		}
		if fdp, ok = r.protos[name]; !ok {
			return fmt.Errorf("the server did not return the file %s", name)
		}
	}
	for _, dep := range fdp.GetDependency() {
		if err := r.build(dep, visiting); err != nil {
			return err
		}
	}
	fd, err := protodesc.NewFile(fdp, r.files)
	if err != nil {
		return err
	}
	return r.files.RegisterFile(fd)
}
