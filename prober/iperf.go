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
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func parseIperfOutput(output string) (float64, error) {
	lines := strings.Split(output, "\n")
	for _, l := range lines {
		if strings.Contains(l, "receiver") {
			cols := strings.Split(l, "  ")
			for _, c := range cols {
				if strings.Contains(c, "Kbits/sec") {
					v := strings.ReplaceAll(c, "Kbits/sec", "")
					return strconv.ParseFloat(strings.TrimSpace(v), 64)
				}
			}
		}
	}

	return 0, errors.New("no throughput found")
}

// ProbeIperf measures the throughput between two hosts using the external iperf3 program.
//
func ProbeIperf(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	probeIperfVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "iperf_probe_duration_millis",
		Help: "Time in milliseconds needed to transmit payload over iperf",
	},
	[]string{"region", "payload_size"})

	registry.MustRegister(probeIperfVec)

	payloadSize := module.Iperf.PayloadSize

	iPath := "/usr/bin/iperf3" // TODO make this configurable

	level.Info(logger).Log("msg", "iperf client started", "target", target)
	c := exec.CommandContext(context.Background(), iPath, "--client", target, "-f", "k")
	level.Info(logger).Log("msg", "iperf client finished", "target", target)

	b, e := c.Output()
	if e != nil {
		level.Error(logger).Log("msg", "error running iperf", "target", target, "err", e)
		return false
	}

	v, e := parseIperfOutput(string(b))
	if e != nil {
		level.Error(logger).Log("msg", "error parsing iperf output", "target", target, "err", e)
		return false
	}

	level.Debug(logger).Log("msg", "successfully measured throughput", "target", target, "value", v)

	p, _ := probeIperfVec.GetMetricWith(prometheus.Labels{
		"payload_size": payloadSize,
		"region":       target,
	})

	p.Set(v)

	return true
}
