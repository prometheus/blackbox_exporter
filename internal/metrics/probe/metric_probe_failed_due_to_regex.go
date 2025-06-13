package probe

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Indicates if probe failed due to regex
type FailedDueToRegex struct {
	prometheus.Gauge
}

func NewFailedDueToRegex() FailedDueToRegex {
	return FailedDueToRegex{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})}
}

func (m FailedDueToRegex) Register(regs ...prometheus.Registerer) FailedDueToRegex {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
