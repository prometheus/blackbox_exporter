package probe

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns the time taken for probe dns lookup in seconds
type DnsLookupTimeSeconds struct {
	prometheus.Gauge
}

func NewDnsLookupTimeSeconds() DnsLookupTimeSeconds {
	return DnsLookupTimeSeconds{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_lookup_time_seconds",
		Help: "Returns the time taken for probe dns lookup in seconds",
	})}
}

func (m DnsLookupTimeSeconds) Register(regs ...prometheus.Registerer) DnsLookupTimeSeconds {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
