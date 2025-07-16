package tcp

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Explicit content matched
type ProbeExpectInfo struct {
	prometheus.Gauge
}

func NewProbeExpectInfo() ProbeExpectInfo {
	return ProbeExpectInfo{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_expect_info",
		Help: "Explicit content matched",
	})}
}

func (m ProbeExpectInfo) Register(regs ...prometheus.Registerer) ProbeExpectInfo {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
