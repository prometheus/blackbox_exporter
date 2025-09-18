package dns

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Displays whether or not the query was executed successfully
type ProbeQuerySucceeded struct {
	prometheus.Gauge
}

func NewProbeQuerySucceeded() ProbeQuerySucceeded {
	return ProbeQuerySucceeded{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_query_succeeded",
		Help: "Displays whether or not the query was executed successfully",
	})}
}

func (m ProbeQuerySucceeded) Register(regs ...prometheus.Registerer) ProbeQuerySucceeded {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
