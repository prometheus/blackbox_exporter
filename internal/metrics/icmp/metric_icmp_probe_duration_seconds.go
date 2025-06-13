package icmp

import (
	"github.com/prometheus/client_golang/prometheus"
)

import (
	"github.com/prometheus/blackbox_exporter/internal/metrics/other"
)

// Duration of icmp request by phase
type ProbeDurationSeconds struct {
	*prometheus.GaugeVec
	extra ProbeDurationSecondsExtra
}

func NewProbeDurationSeconds() ProbeDurationSeconds {
	labels := []string{other.AttrPhase("").Key()}
	return ProbeDurationSeconds{GaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_icmp_duration_seconds",
		Help: "Duration of icmp request by phase",
	}, labels)}
}

func (m ProbeDurationSeconds) With(phase other.AttrPhase, extras ...interface{}) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(phase.Value())
}

// Deprecated: Use [ProbeDurationSeconds.With] instead
func (m ProbeDurationSeconds) WithLabelValues(lvs ...string) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(lvs...)
}

type ProbeDurationSecondsExtra struct {
}
