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
	"fmt"
	"strconv"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/go-ping/ping"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/blackbox_exporter/config"
)

func ProbeICMP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_icmp_duration_seconds",
			Help: "Duration of icmp request by phase",
		}, []string{"phase"})

		hopLimitGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_icmp_reply_hop_limit",
			Help: "Replied packet hop limit (TTL for ipv4)",
		})
	)

	for _, lv := range []string{"resolve", "setup", "rtt"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)

	dstIPAddr, lookupTime, err := chooseProtocol(ctx, module.ICMP.IPProtocol, module.ICMP.IPProtocolFallback, target, registry, logger)
	if err != nil {
		level.Warn(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}

	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)

	pinger := ping.New(dstIPAddr.String())

	pinger.Timeout = module.Timeout

	pinger.SetLogger(icmpLogger{logger})

	var (
		setupStart time.Time
		setupDone  bool
	)

	pinger.OnSetup = func() {
		if !setupDone {
			durationGaugeVec.WithLabelValues("setup").Add(time.Since(setupStart).Seconds())
			setupDone = true
		}
		level.Info(logger).Log("msg", "Using source address", "srcIP", pinger.Source)
	}

	pinger.OnSend = func(pkt *ping.Packet) {
		level.Info(logger).Log("msg", "Creating ICMP packet", "seq", strconv.Itoa(pkt.Seq))
		level.Info(logger).Log("msg", "Waiting for reply packets")
	}

	pinger.OnRecv = func(pkt *ping.Packet) {
		if pkt.Seq == 0 && pkt.Ttl > 0 {
			registry.MustRegister(hopLimitGauge)
			hopLimitGauge.Set(float64(pkt.Ttl))
		}

		level.Info(logger).Log("msg", "Found matching reply packet", "seq", strconv.Itoa(pkt.Seq))
	}

	pinger.OnDuplicateRecv = func(pkt *ping.Packet) {
		level.Info(logger).Log("msg", "Duplicate packet received", "seq", strconv.Itoa(pkt.Seq))
	}

	pinger.OnFinish = func(stats *ping.Statistics) {
		durationGaugeVec.WithLabelValues("rtt").Set(stats.AvgRtt.Seconds())
		level.Info(logger).Log("msg", "Probe finished", "packets_sent", stats.PacketsSent, "packets_received", stats.PacketsRecv)
	}

	// TODO: module.ICMP.DontFragment

	if module.ICMP.PayloadSize != 0 {
		pinger.Size = module.ICMP.PayloadSize
	}

	pinger.Count = 1

	pinger.RecordRtts = false

	pinger.Source = module.ICMP.SourceIPAddress

	setupStart = time.Now()

	level.Info(logger).Log("msg", "Creating socket")

	if err := pinger.Run(); err != nil {
		level.Info(logger).Log("msg", "failed to run ping", "err", err.Error())
		return false
	}

	return pinger.Count == pinger.PacketsSent && pinger.PacketsRecv == pinger.PacketsSent
}

type icmpLogger struct {
	logger log.Logger
}

func (l icmpLogger) Fatalf(format string, v ...interface{}) {
	level.Error(l.logger).Log("msg", fmt.Sprintf(format, v...))
}

func (l icmpLogger) Errorf(format string, v ...interface{}) {
	level.Error(l.logger).Log("msg", fmt.Sprintf(format, v...))
}

func (l icmpLogger) Warnf(format string, v ...interface{}) {
	level.Warn(l.logger).Log("msg", fmt.Sprintf(format, v...))
}

func (l icmpLogger) Infof(format string, v ...interface{}) {
	level.Info(l.logger).Log("msg", fmt.Sprintf(format, v...))
}

func (l icmpLogger) Debugf(format string, v ...interface{}) {
	level.Debug(l.logger).Log("msg", fmt.Sprintf(format, v...))
}
