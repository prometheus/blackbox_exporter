package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Response HTTP status code
type ProbeStatusCode struct {
	prometheus.Gauge
}

func NewProbeStatusCode() ProbeStatusCode {
	return ProbeStatusCode{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_http_status_code",
		Help: "Response HTTP status code",
	})}
}

func (m ProbeStatusCode) Register(regs ...prometheus.Registerer) ProbeStatusCode {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
