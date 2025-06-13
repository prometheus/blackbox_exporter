package icmp

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Replied packet hop limit (TTL for ipv4)
type ProbeReplyHopLimit struct {
	prometheus.Gauge
}

func NewProbeReplyHopLimit() ProbeReplyHopLimit {
	return ProbeReplyHopLimit{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_icmp_reply_hop_limit",
		Help: "Replied packet hop limit (TTL for ipv4)",
	})}
}

func (m ProbeReplyHopLimit) Register(regs ...prometheus.Registerer) ProbeReplyHopLimit {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
