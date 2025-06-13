package probe

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Specifies the hash of IP address. It's useful to detect if the IP address changes.
type IpAddrHash struct {
	prometheus.Gauge
}

func NewIpAddrHash() IpAddrHash {
	return IpAddrHash{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_addr_hash",
		Help: "Specifies the hash of IP address. It's useful to detect if the IP address changes.",
	})}
}

func (m IpAddrHash) Register(regs ...prometheus.Registerer) IpAddrHash {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
