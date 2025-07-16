package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// The number of redirects
type ProbeRedirects struct {
	prometheus.Gauge
}

func NewProbeRedirects() ProbeRedirects {
	return ProbeRedirects{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_http_redirects",
		Help: "The number of redirects",
	})}
}

func (m ProbeRedirects) Register(regs ...prometheus.Registerer) ProbeRedirects {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
