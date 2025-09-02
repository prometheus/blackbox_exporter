package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Indicates if SSL was used for the final redirect
type ProbeSsl struct {
	prometheus.Gauge
}

func NewProbeSsl() ProbeSsl {
	return ProbeSsl{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_http_ssl",
		Help: "Indicates if SSL was used for the final redirect",
	})}
}

func (m ProbeSsl) Register(regs ...prometheus.Registerer) ProbeSsl {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
