package ssl

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns earliest SSL cert expiry date
type ProbeEarliestCertExpiry struct {
	prometheus.Gauge
}

func NewProbeEarliestCertExpiry() ProbeEarliestCertExpiry {
	return ProbeEarliestCertExpiry{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: "Returns earliest SSL cert expiry date",
	})}
}

func (m ProbeEarliestCertExpiry) Register(regs ...prometheus.Registerer) ProbeEarliestCertExpiry {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
