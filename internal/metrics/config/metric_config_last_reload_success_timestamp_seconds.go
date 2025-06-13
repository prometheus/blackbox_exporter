package config

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Timestamp of the last successful configuration reload
type LastReloadSuccessTimestampSeconds struct {
	prometheus.Gauge
}

func NewLastReloadSuccessTimestampSeconds() LastReloadSuccessTimestampSeconds {
	return LastReloadSuccessTimestampSeconds{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blackbox_exporter_config_last_reload_success_timestamp_seconds",
		Help: "Timestamp of the last successful configuration reload",
	})}
}

func (m LastReloadSuccessTimestampSeconds) Register(regs ...prometheus.Registerer) LastReloadSuccessTimestampSeconds {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
