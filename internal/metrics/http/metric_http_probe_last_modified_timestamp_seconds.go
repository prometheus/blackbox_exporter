package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns the Last-Modified HTTP response header in unixtime
type ProbeLastModifiedTimestampSeconds struct {
	prometheus.Gauge
}

func NewProbeLastModifiedTimestampSeconds() ProbeLastModifiedTimestampSeconds {
	return ProbeLastModifiedTimestampSeconds{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_http_last_modified_timestamp_seconds",
		Help: "Returns the Last-Modified HTTP response header in unixtime",
	})}
}

func (m ProbeLastModifiedTimestampSeconds) Register(regs ...prometheus.Registerer) ProbeLastModifiedTimestampSeconds {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
