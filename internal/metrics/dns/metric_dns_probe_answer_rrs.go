package dns

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Returns number of entries in the answer resource record list
type ProbeAnswerRrs struct {
	prometheus.Gauge
}

func NewProbeAnswerRrs() ProbeAnswerRrs {
	return ProbeAnswerRrs{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_answer_rrs",
		Help: "Returns number of entries in the answer resource record list",
	})}
}

func (m ProbeAnswerRrs) Register(regs ...prometheus.Registerer) ProbeAnswerRrs {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
