package dns

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns number of entries in the additional resource record list
type ProbeAdditionalRrs struct {
	prometheus.Gauge
}

func NewProbeAdditionalRrs() ProbeAdditionalRrs {
	return ProbeAdditionalRrs{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_additional_rrs",
		Help: "Returns number of entries in the additional resource record list",
	})}
}

func (m ProbeAdditionalRrs) Register(regs ...prometheus.Registerer) ProbeAdditionalRrs {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
