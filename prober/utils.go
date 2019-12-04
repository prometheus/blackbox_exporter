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
	"bytes"
	"context"
	"fmt"
	"github.com/prometheus/blackbox_exporter/config"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/prometheus/client_golang/prometheus"
)

// Returns the IP for the IPProtocol and lookup time.
func chooseProtocol(ctx context.Context, IPProtocol string, fallbackIPProtocol bool, target string, registry *prometheus.Registry, logger log.Logger) (ip *net.IPAddr, lookupTime float64, err error) {
	var fallbackProtocol string
	probeDNSLookupTimeSeconds := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_lookup_time_seconds",
		Help: "Returns the time taken for probe dns lookup in seconds",
	})

	probeIPProtocolGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_protocol",
		Help: "Specifies whether probe ip protocol is IP4 or IP6",
	})
	registry.MustRegister(probeIPProtocolGauge)
	registry.MustRegister(probeDNSLookupTimeSeconds)

	if IPProtocol == "ip6" || IPProtocol == "" {
		IPProtocol = "ip6"
		fallbackProtocol = "ip4"
	} else {
		IPProtocol = "ip4"
		fallbackProtocol = "ip6"
	}

	level.Info(logger).Log("msg", "Resolving target address", "ip_protocol", IPProtocol)
	resolveStart := time.Now()

	defer func() {
		lookupTime = time.Since(resolveStart).Seconds()
		probeDNSLookupTimeSeconds.Add(lookupTime)
	}()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		level.Error(logger).Log("msg", "Resolution with IP protocol failed", "err", err)
		return nil, 0.0, err
	}

	// Return the IP in the requested protocol.
	var fallback *net.IPAddr
	for _, ip := range ips {
		switch IPProtocol {
		case "ip4":
			if ip.IP.To4() != nil {
				level.Info(logger).Log("msg", "Resolved target address", "ip", ip.String())
				probeIPProtocolGauge.Set(4)
				return &ip, lookupTime, nil
			}

			// ip4 as fallback
			fallback = &ip

		case "ip6":
			if ip.IP.To4() == nil {
				level.Info(logger).Log("msg", "Resolved target address", "ip", ip.String())
				probeIPProtocolGauge.Set(6)
				return &ip, lookupTime, nil
			}

			// ip6 as fallback
			fallback = &ip
		}
	}

	// Unable to find ip and no fallback set.
	if fallback == nil || !fallbackIPProtocol {
		return nil, 0.0, fmt.Errorf("unable to find ip; no fallback")
	}

	// Use fallback ip protocol.
	if fallbackProtocol == "ip4" {
		probeIPProtocolGauge.Set(4)
	} else {
		probeIPProtocolGauge.Set(6)
	}
	level.Info(logger).Log("msg", "Resolved target address", "ip", fallback.String())
	return fallback, lookupTime, nil
}

// Returns the result of cmdline executed
func executeCmd(proc config.CMDProbe, timeout time.Duration) (executeResult float64, err error) {
	var (
		cmd *exec.Cmd
	)

	// Execute timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if proc.ScriptMode {
		proc.CmdLine = append([]string{proc.ScriptPath}, proc.CmdLine...)
		cmd = exec.CommandContext(ctx, proc.Executable, proc.CmdLine...)
	} else {
		cmd = exec.CommandContext(ctx, proc.Executable, "-c", strings.Join(proc.CmdLine, " "))
	}

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	if err := cmd.Start(); err != nil {
		executeResult := -1.0
		return executeResult, err
	}

	if err := cmd.Wait(); err != nil {
		executeResult := -124.0
		return executeResult, err
	}

	cmdStdout := fmt.Sprint(cmd.Stdout)
	executeResult, err = strconv.ParseFloat(strings.TrimSpace(cmdStdout), 64)
	if err != nil {
		executeResult := -128.0
		return executeResult, err
	}
	return executeResult, nil
}
