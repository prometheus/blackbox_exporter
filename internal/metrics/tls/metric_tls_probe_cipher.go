package tls

import (
	"github.com/prometheus/client_golang/prometheus"
)

import (
	"github.com/prometheus/blackbox_exporter/internal/metrics/other"
)

// Contains TLS cipher information
type ProbeCipher struct {
	*prometheus.GaugeVec
	extra ProbeCipherExtra
}

func NewProbeCipher() ProbeCipher {
	labels := []string{other.AttrCipher("").Key()}
	return ProbeCipher{GaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_tls_cipher_info",
		Help: "Contains TLS cipher information",
	}, labels)}
}

func (m ProbeCipher) With(cipher other.AttrCipher, extras ...interface{}) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(cipher.Value())
}

// Deprecated: Use [ProbeCipher.With] instead
func (m ProbeCipher) WithLabelValues(lvs ...string) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(lvs...)
}

type ProbeCipherExtra struct {
}
