package ssl

import (
	"github.com/prometheus/client_golang/prometheus"
)

import (
	"github.com/prometheus/blackbox_exporter/internal/metrics/other"
)

// Contains SSL leaf certificate information
type ProbeLastChainInfo struct {
	*prometheus.GaugeVec
	extra ProbeLastChainInfoExtra
}

func NewProbeLastChainInfo() ProbeLastChainInfo {
	labels := []string{other.AttrFingerprintSha256("").Key(), other.AttrIssuer("").Key(), other.AttrSerialnumber("").Key(), other.AttrSubject("").Key(), other.AttrSubjectalternative("").Key()}
	return ProbeLastChainInfo{GaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_ssl_last_chain_info",
		Help: "Contains SSL leaf certificate information",
	}, labels)}
}

func (m ProbeLastChainInfo) With(fingerprintSha256 other.AttrFingerprintSha256, issuer other.AttrIssuer, serialnumber other.AttrSerialnumber, subject other.AttrSubject, subjectalternative other.AttrSubjectalternative, extras ...interface{}) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(fingerprintSha256.Value(), issuer.Value(), serialnumber.Value(), subject.Value(), subjectalternative.Value())
}

// Deprecated: Use [ProbeLastChainInfo.With] instead
func (m ProbeLastChainInfo) WithLabelValues(lvs ...string) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(lvs...)
}

type ProbeLastChainInfoExtra struct {
}
