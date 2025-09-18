package config

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Blackbox exporter config loaded successfully
type LastReloadSuccessful struct {
	prometheus.Gauge
}

func NewLastReloadSuccessful() LastReloadSuccessful {
	return LastReloadSuccessful{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blackbox_exporter_config_last_reload_successful",
		Help: "Blackbox exporter config loaded successfully",
	})}
}

func (m LastReloadSuccessful) Register(regs ...prometheus.Registerer) LastReloadSuccessful {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
