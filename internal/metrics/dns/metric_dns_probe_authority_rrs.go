package dns

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns number of entries in the authority resource record list
type ProbeAuthorityRrs struct {
	prometheus.Gauge
}

func NewProbeAuthorityRrs() ProbeAuthorityRrs {
	return ProbeAuthorityRrs{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_authority_rrs",
		Help: "Returns number of entries in the authority resource record list",
	})}
}

func (m ProbeAuthorityRrs) Register(regs ...prometheus.Registerer) ProbeAuthorityRrs {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
