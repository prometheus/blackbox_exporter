package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Length of uncompressed response body
type ProbeUncompressedBodyLength struct {
	prometheus.Gauge
}

func NewProbeUncompressedBodyLength() ProbeUncompressedBodyLength {
	return ProbeUncompressedBodyLength{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_http_uncompressed_body_length",
		Help: "Length of uncompressed response body",
	})}
}

func (m ProbeUncompressedBodyLength) Register(regs ...prometheus.Registerer) ProbeUncompressedBodyLength {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
