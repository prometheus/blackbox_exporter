package probe

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Specifies whether probe ip protocol is IP4 or IP6
type IpProtocol struct {
	prometheus.Gauge
}

func NewIpProtocol() IpProtocol {
	return IpProtocol{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_protocol",
		Help: "Specifies whether probe ip protocol is IP4 or IP6",
	})}
}

func (m IpProtocol) Register(regs ...prometheus.Registerer) IpProtocol {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
