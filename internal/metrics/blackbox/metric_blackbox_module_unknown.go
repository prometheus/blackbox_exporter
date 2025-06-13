package blackbox

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Count of unknown modules requested by probes
type ModuleUnknown struct {
	prometheus.Counter
}

func NewModuleUnknown() ModuleUnknown {
	return ModuleUnknown{Counter: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blackbox_module_unknown_total",
		Help: "Count of unknown modules requested by probes",
	})}
}

func (m ModuleUnknown) Register(regs ...prometheus.Registerer) ModuleUnknown {
	if regs == nil {
		prometheus.DefaultRegisterer.MustRegister(m)
	}
	for _, reg := range regs {
		reg.MustRegister(m)
	}
	return m
}
