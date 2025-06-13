package probe

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns how long the probe took to complete in seconds
type DurationSeconds struct {
	prometheus.Gauge
}

func NewDurationSeconds() DurationSeconds {
	return DurationSeconds{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})}
}

func (m DurationSeconds) Register(regs ...prometheus.Registerer) DurationSeconds {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
