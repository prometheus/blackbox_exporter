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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/prometheus/blackbox_exporter/config"
)

// probeGRPCUnaryMethod calls the unary method configured in cfg and validates
// its response. It returns the peer of the call so that the caller can
// report TLS metrics, or nil if the method was never invoked.
func probeGRPCUnaryMethod(ctx context.Context, conn grpc.ClientConnInterface, cfg *config.GRPCUnaryMethod, md metadata.MD,
	registry *prometheus.Registry, durationGaugeVec *prometheus.GaugeVec, logger *slog.Logger,
) (success bool, serverPeer *peer.Peer) {
	var (
		statusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_grpc_status_code",
			Help: "Response gRPC status code",
		})

		reflectionStatusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_grpc_reflection_status_code",
			Help: "gRPC status code of the server reflection request used to resolve the probed method",
		})

		responseSizeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_grpc_response_size_bytes",
			Help: "Size of the gRPC response message in bytes, as encoded in protobuf",
		})

		probeFailedDueToRegex = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_regex",
			Help: "Indicates if probe failed due to regex",
		})

		probeFailedDueToCEL = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_cel",
			Help: "Indicates if probe failed due to CEL expression not matching",
		})
	)

	ctx = metadata.NewOutgoingContext(ctx, md)

	serviceName, methodName, err := cfg.ServiceAndMethod()
	if err != nil {
		logger.Error("Invalid gRPC method", "err", err)
		return false, nil
	}

	var files *protoregistry.Files
	if cfg.DescriptorSetFile != "" {
		files, err = cfg.DescriptorFiles()
		if err != nil {
			logger.Error("Error loading descriptor set", "err", err)
			return false, nil
		}
	} else {
		registry.MustRegister(reflectionStatusCodeGauge)
		durationGaugeVec.WithLabelValues("reflection")
		reflectionStart := time.Now()
		files, err = resolveServiceDescriptors(ctx, conn, serviceName)
		durationGaugeVec.WithLabelValues("reflection").Add(time.Since(reflectionStart).Seconds())
		reflectionStatusCodeGauge.Set(float64(status.Code(err)))
		if err != nil {
			logger.Error("Error resolving gRPC method using server reflection", "service", serviceName, "err", err)
			return false, nil
		}
	}

	methodDesc, err := config.FindGRPCMethod(files, serviceName, methodName)
	if err != nil {
		logger.Error("Error looking up gRPC method", "err", err)
		return false, nil
	}

	types := dynamicpb.NewTypes(files)
	request := dynamicpb.NewMessage(methodDesc.Input())
	if cfg.Request != "" {
		if err := (protojson.UnmarshalOptions{Resolver: types}).Unmarshal([]byte(cfg.Request), request); err != nil {
			logger.Error("Error building gRPC request message", "type", methodDesc.Input().FullName(), "err", err)
			return false, nil
		}
	}
	response := dynamicpb.NewMessage(methodDesc.Output())

	fullMethod := "/" + serviceName + "/" + methodName
	logger.Debug("Calling gRPC method", "method", fullMethod)
	serverPeer = new(peer.Peer)
	callStart := time.Now()
	err = conn.Invoke(ctx, fullMethod, request, response, grpc.Peer(serverPeer))
	durationGaugeVec.WithLabelValues("check").Add(time.Since(callStart).Seconds())
	if serverPeer.Addr == nil {
		serverPeer = nil
	}

	code := status.Code(err)
	registry.MustRegister(statusCodeGauge)
	statusCodeGauge.Set(float64(code))
	if !cfg.IsValidStatusCode(code) {
		logger.Error("gRPC method returned an invalid status code", "method", fullMethod, "code", config.GRPCStatusCode(code), "err", err)
		return false, serverPeer
	}
	if code != codes.OK {
		// There is no response message to validate.
		logger.Debug("gRPC method returned an accepted status code", "method", fullMethod, "code", config.GRPCStatusCode(code))
		return true, serverPeer
	}

	registry.MustRegister(responseSizeGauge)
	responseSizeGauge.Set(float64(proto.Size(response)))

	hasRegexps := len(cfg.FailIfResponseMatchesRegexp) > 0 || len(cfg.FailIfResponseNotMatchesRegexp) > 0
	hasCEL := cfg.FailIfResponseJSONMatchesCEL != nil || cfg.FailIfResponseJSONNotMatchesCEL != nil
	if !hasRegexps && !hasCEL {
		return true, serverPeer
	}

	responseJSON, err := marshalResponseJSON(response, types)
	if err != nil {
		logger.Error("Error encoding gRPC response as JSON", "err", err)
		return false, serverPeer
	}
	logger.Debug("Received gRPC response", "response", string(responseJSON))

	success = true
	if hasRegexps {
		registry.MustRegister(probeFailedDueToRegex)
		if matchGRPCResponseRegexps(responseJSON, cfg, logger) {
			probeFailedDueToRegex.Set(0)
		} else {
			probeFailedDueToRegex.Set(1)
			success = false
		}
	}
	if success && hasCEL {
		registry.MustRegister(probeFailedDueToCEL)
		if matchGRPCResponseCEL(ctx, responseJSON, cfg, logger) {
			probeFailedDueToCEL.Set(0)
		} else {
			probeFailedDueToCEL.Set(1)
			success = false
		}
	}
	return success, serverPeer
}

// marshalResponseJSON encodes msg using the canonical protobuf JSON mapping.
// The protojson output is deliberately unstable with respect to whitespace,
// so it is compacted to give regular expressions a predictable input.
func marshalResponseJSON(msg *dynamicpb.Message, types *dynamicpb.Types) ([]byte, error) {
	b, err := (protojson.MarshalOptions{Resolver: types}).Marshal(msg)
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, b); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

func matchGRPCResponseRegexps(response []byte, cfg *config.GRPCUnaryMethod, logger *slog.Logger) bool {
	for _, expression := range cfg.FailIfResponseMatchesRegexp {
		if expression.Match(response) {
			logger.Error("Response matched regular expression", "regexp", expression)
			return false
		}
	}
	for _, expression := range cfg.FailIfResponseNotMatchesRegexp {
		if !expression.Match(response) {
			logger.Error("Response did not match regular expression", "regexp", expression)
			return false
		}
	}
	return true
}

func matchGRPCResponseCEL(ctx context.Context, response []byte, cfg *config.GRPCUnaryMethod, logger *slog.Logger) bool {
	var responseJSON any
	if err := json.Unmarshal(response, &responseJSON); err != nil {
		logger.Error("Error unmarshalling gRPC response JSON", "err", err)
		return false
	}
	evalPayload := map[string]any{"body": responseJSON}

	evaluate := func(program *config.CELProgram) (bool, bool) {
		result, details, err := program.ContextEval(ctx, evalPayload)
		if err != nil {
			logger.Error("Error evaluating CEL expression", "err", err)
			return false, false
		}
		if result.Type() != cel.BoolType {
			logger.Error("CEL evaluation result is not a boolean", "details", details)
			return false, false
		}
		return result.Value().(bool), true
	}

	if cfg.FailIfResponseJSONMatchesCEL != nil {
		matched, ok := evaluate(cfg.FailIfResponseJSONMatchesCEL)
		if !ok {
			return false
		}
		if matched {
			logger.Error("Response matched CEL expression", "expression", cfg.FailIfResponseJSONMatchesCEL.Expression)
			return false
		}
	}
	if cfg.FailIfResponseJSONNotMatchesCEL != nil {
		matched, ok := evaluate(cfg.FailIfResponseJSONNotMatchesCEL)
		if !ok {
			return false
		}
		if !matched {
			logger.Error("Response did not match CEL expression", "expression", cfg.FailIfResponseJSONNotMatchesCEL.Expression)
			return false
		}
	}
	return true
}
