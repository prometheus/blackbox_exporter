package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Indicates if probe failed due to CEL expression not matching
type ProbeFailedDueToCel struct {
	prometheus.Gauge
}

func NewProbeFailedDueToCel() ProbeFailedDueToCel {
	return ProbeFailedDueToCel{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_cel",
		Help: "Indicates if probe failed due to CEL expression not matching",
	})}
}

func (m ProbeFailedDueToCel) Register(regs ...prometheus.Registerer) ProbeFailedDueToCel {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
