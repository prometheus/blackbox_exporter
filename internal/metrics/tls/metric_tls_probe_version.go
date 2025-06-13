package tls

import (
	"github.com/prometheus/client_golang/prometheus"
)

import (
	"github.com/prometheus/blackbox_exporter/internal/metrics/other"
)

// Contains TLS version information
type ProbeVersion struct {
	*prometheus.GaugeVec
	extra ProbeVersionExtra
}

func NewProbeVersion() ProbeVersion {
	labels := []string{other.AttrVersion("").Key()}
	return ProbeVersion{GaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_tls_version_info",
		Help: "Contains TLS version information",
	}, labels)}
}

func (m ProbeVersion) With(version other.AttrVersion, extras ...interface{}) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(version.Value())
}

// Deprecated: Use [ProbeVersion.With] instead
func (m ProbeVersion) WithLabelValues(lvs ...string) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(lvs...)
}

type ProbeVersionExtra struct {
}
