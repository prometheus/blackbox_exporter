package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns the version of HTTP of the probe response
type ProbeVersion struct {
	prometheus.Gauge
}

func NewProbeVersion() ProbeVersion {
	return ProbeVersion{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_http_version",
		Help: "Returns the version of HTTP of the probe response",
	})}
}

func (m ProbeVersion) Register(regs ...prometheus.Registerer) ProbeVersion {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
