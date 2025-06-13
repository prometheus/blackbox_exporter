package probe

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Displays whether or not the probe was a success
type Success struct {
	prometheus.Gauge
}

func NewSuccess() Success {
	return Success{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})}
}

func (m Success) Register(regs ...prometheus.Registerer) Success {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
