package dns

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns the serial number of the zone
type ProbeSerial struct {
	prometheus.Gauge
}

func NewProbeSerial() ProbeSerial {
	return ProbeSerial{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_serial",
		Help: "Returns the serial number of the zone",
	})}
}

func (m ProbeSerial) Register(regs ...prometheus.Registerer) ProbeSerial {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
