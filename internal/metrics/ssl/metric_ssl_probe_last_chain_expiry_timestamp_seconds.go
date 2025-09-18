package ssl

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns last SSL chain expiry timestamp
type ProbeLastChainExpiryTimestampSeconds struct {
	prometheus.Gauge
}

func NewProbeLastChainExpiryTimestampSeconds() ProbeLastChainExpiryTimestampSeconds {
	return ProbeLastChainExpiryTimestampSeconds{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_last_chain_expiry_timestamp_seconds",
		Help: "Returns last SSL chain expiry timestamp",
	})}
}

func (m ProbeLastChainExpiryTimestampSeconds) Register(regs ...prometheus.Registerer) ProbeLastChainExpiryTimestampSeconds {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
