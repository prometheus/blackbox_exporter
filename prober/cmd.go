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

package prober

import (
	"context"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func executeCMD(module config.Module, logger log.Logger) (executeResult float64, err error) {
	executeResult, err = executeCmd(module.CMD, module.Timeout)
	if err != nil {
		level.Error(logger).Log("msg", "Error execute cmdline", "err", err)
		return executeResult, err
	}
	return executeResult, nil
}

func ProbeCMD(_ context.Context, _ string, module config.Module, registry *prometheus.Registry, logger log.Logger) bool {
	probeCMDExecuteResult := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_cmd_execute_result",
		Help: "Returns cmdline executed result",
	})
	registry.MustRegister(probeCMDExecuteResult)

	executeResult, err := executeCMD(module, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error execute CMD", "err", err)
		probeCMDExecuteResult.Set(executeResult)
		return false
	}
	level.Info(logger).Log("msg", "Successfully executed")
	probeCMDExecuteResult.Set(executeResult)
	return true
}
