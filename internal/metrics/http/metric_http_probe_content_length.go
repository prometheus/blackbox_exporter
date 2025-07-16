package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Length of http content response
type ProbeContentLength struct {
	prometheus.Gauge
}

func NewProbeContentLength() ProbeContentLength {
	return ProbeContentLength{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_http_content_length",
		Help: "Length of http content response",
	})}
}

func (m ProbeContentLength) Register(regs ...prometheus.Registerer) ProbeContentLength {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
