package grpc

import (
	"github.com/prometheus/client_golang/prometheus"
)

import (
	"github.com/prometheus/blackbox_exporter/internal/metrics/other"
)

// Response HealthCheck response
type ProbeHealthcheckResponse struct {
	*prometheus.GaugeVec
	extra ProbeHealthcheckResponseExtra
}

func NewProbeHealthcheckResponse() ProbeHealthcheckResponse {
	labels := []string{other.AttrServingStatus("").Key()}
	return ProbeHealthcheckResponse{GaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_grpc_healthcheck_response",
		Help: "Response HealthCheck response",
	}, labels)}
}

func (m ProbeHealthcheckResponse) With(servingStatus other.AttrServingStatus, extras ...interface{}) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(servingStatus.Value())
}

// Deprecated: Use [ProbeHealthcheckResponse.With] instead
func (m ProbeHealthcheckResponse) WithLabelValues(lvs ...string) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(lvs...)
}

type ProbeHealthcheckResponseExtra struct {
}
