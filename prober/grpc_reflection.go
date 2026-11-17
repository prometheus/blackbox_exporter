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
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	reflectionalphapb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// reflectionStream is the subset of the server reflection stream used by
// the prober. It is implemented by the v1 client stream directly and by
// v1alphaStream for servers that only implement the older v1alpha API.
type reflectionStream interface {
	Send(*reflectionpb.ServerReflectionRequest) error
	Recv() (*reflectionpb.ServerReflectionResponse, error)
	CloseSend() error
}

// v1alphaStream adapts a v1alpha reflection stream to the v1 message types.
// Both versions share the same wire format, so messages are converted by
// re-encoding them.
type v1alphaStream struct {
	stream grpc.BidiStreamingClient[reflectionalphapb.ServerReflectionRequest, reflectionalphapb.ServerReflectionResponse] //nolint:staticcheck // v1alpha is still the only reflection API on many servers.
}

func (s v1alphaStream) Send(req *reflectionpb.ServerReflectionRequest) error {
	var alphaReq reflectionalphapb.ServerReflectionRequest //nolint:staticcheck // See v1alphaStream.
	if err := convertMessage(req, &alphaReq); err != nil {
		return err
	}
	return s.stream.Send(&alphaReq)
}

func (s v1alphaStream) Recv() (*reflectionpb.ServerReflectionResponse, error) {
	alphaResp, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	var resp reflectionpb.ServerReflectionResponse
	if err := convertMessage(alphaResp, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s v1alphaStream) CloseSend() error {
	return s.stream.CloseSend()
}

func convertMessage(from, to proto.Message) error {
	b, err := proto.Marshal(from)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, to)
}

// grpcReflectionClient resolves service descriptors using the gRPC server
// reflection protocol.
type grpcReflectionClient struct {
	stream reflectionStream
}

// resolveServiceDescriptors fetches the file that defines service, together
// with all of its transitive dependencies, from the server reflection service
// and returns them as a protoregistry.Files.
func resolveServiceDescriptors(ctx context.Context, conn grpc.ClientConnInterface, service string) (*protoregistry.Files, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	first := &reflectionpb.ServerReflectionRequest{
		MessageRequest: &reflectionpb.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: service},
	}

	stream, err := reflectionpb.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	if err != nil {
		return nil, err
	}
	client := &grpcReflectionClient{stream: stream}
	resp, err := client.exchange(first)
	if status.Code(err) == codes.Unimplemented {
		// The server may only implement the older v1alpha API.
		alpha, alphaErr := reflectionalphapb.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
		if alphaErr != nil {
			return nil, alphaErr
		}
		client = &grpcReflectionClient{stream: v1alphaStream{stream: alpha}}
		resp, err = client.exchange(first)
	}
	if err != nil {
		return nil, err
	}
	defer client.stream.CloseSend()

	fetched := map[string]*descriptorpb.FileDescriptorProto{}
	if err := addFileDescriptors(fetched, resp); err != nil {
		return nil, err
	}

	// Fetch any dependency that was not included in the response. Most
	// servers send all transitive dependencies up front, so this is usually
	// a no-op.
	for {
		missing := missingDependencies(fetched)
		if len(missing) == 0 {
			break
		}
		for _, name := range missing {
			resp, err := client.exchange(&reflectionpb.ServerReflectionRequest{
				MessageRequest: &reflectionpb.ServerReflectionRequest_FileByFilename{FileByFilename: name},
			})
			if err != nil {
				fd, globalErr := protoregistry.GlobalFiles.FindFileByPath(name)
				if globalErr != nil {
					return nil, fmt.Errorf("fetching dependency %q: %w", name, err)
				}
				fetched[name] = protodesc.ToFileDescriptorProto(fd)
				continue
			}
			if err := addFileDescriptors(fetched, resp); err != nil {
				return nil, err
			}
			if _, ok := fetched[name]; !ok {
				return nil, fmt.Errorf("server reflection did not return requested file %q", name)
			}
		}
	}

	set := &descriptorpb.FileDescriptorSet{}
	for _, fd := range fetched {
		set.File = append(set.File, fd)
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, fmt.Errorf("building descriptors from server reflection: %w", err)
	}
	return files, nil
}

// exchange sends a single request and waits for its response. Errors
// reported by the reflection service are returned as gRPC status errors.
func (c *grpcReflectionClient) exchange(req *reflectionpb.ServerReflectionRequest) (*reflectionpb.ServerReflectionResponse, error) {
	if err := c.stream.Send(req); err != nil {
		// The actual error is reported by Recv.
		_, recvErr := c.stream.Recv()
		if recvErr != nil {
			return nil, recvErr
		}
		return nil, err
	}
	resp, err := c.stream.Recv()
	if err != nil {
		return nil, err
	}
	if errResp := resp.GetErrorResponse(); errResp != nil {
		return nil, status.Error(codes.Code(errResp.GetErrorCode()), errResp.GetErrorMessage())
	}
	return resp, nil
}

func addFileDescriptors(fetched map[string]*descriptorpb.FileDescriptorProto, resp *reflectionpb.ServerReflectionResponse) error {
	fdResp := resp.GetFileDescriptorResponse()
	if fdResp == nil {
		return fmt.Errorf("unexpected server reflection response %T", resp.GetMessageResponse())
	}
	for _, raw := range fdResp.GetFileDescriptorProto() {
		fd := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(raw, fd); err != nil {
			return fmt.Errorf("decoding file descriptor from server reflection: %w", err)
		}
		fetched[fd.GetName()] = fd
	}
	return nil
}

func missingDependencies(fetched map[string]*descriptorpb.FileDescriptorProto) []string {
	seen := map[string]bool{}
	var missing []string
	for _, fd := range fetched {
		for _, dep := range fd.GetDependency() {
			if _, ok := fetched[dep]; !ok && !seen[dep] {
				seen[dep] = true
				missing = append(missing, dep)
			}
		}
	}
	return missing
}
