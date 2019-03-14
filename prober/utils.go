package prober

import (
	"net"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/prometheus/client_golang/prometheus"
)

// Returns the IP for the IPProtocol and lookup time.
func chooseProtocol(IPProtocol string, fallbackIPProtocol bool, target string, registry *prometheus.Registry, logger log.Logger) (ip *net.IPAddr, lookupTime float64, err error) {
	var fallbackProtocol string
	probeDNSLookupTimeSeconds := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_lookup_time_seconds",
		Help: "Returns the time taken for probe dns lookup in seconds",
	})

	probeIPProtocolGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_protocol",
		Help: "Specifies whether probe ip protocol is IP4 or IP6",
	})
	registry.MustRegister(probeIPProtocolGauge)
	registry.MustRegister(probeDNSLookupTimeSeconds)

	if IPProtocol == "ip6" || IPProtocol == "" {
		IPProtocol = "ip6"
		fallbackProtocol = "ip4"
	} else {
		IPProtocol = "ip4"
		fallbackProtocol = "ip6"
	}

	if IPProtocol == "ip6" {
		fallbackProtocol = "ip4"
	} else {
		fallbackProtocol = "ip6"
	}

	level.Info(logger).Log("msg", "Resolving target address", "ip_protocol", IPProtocol)
	resolveStart := time.Now()

	defer func() {
		lookupTime = time.Since(resolveStart).Seconds()
		probeDNSLookupTimeSeconds.Add(lookupTime)
	}()

	ip, err = net.ResolveIPAddr(IPProtocol, target)
	if err != nil {
		if !fallbackIPProtocol {
			level.Error(logger).Log("msg", "Resolution with IP protocol failed (fallback_ip_protocol is false):", "err", err)
		} else {
			level.Warn(logger).Log("msg", "Resolution with IP protocol failed, attempting fallback protocol", "fallback_protocol", fallbackProtocol, "err", err)
			ip, err = net.ResolveIPAddr(fallbackProtocol, target)
		}

		if err != nil {
			if IPProtocol == "ip6" {
				probeIPProtocolGauge.Set(6)
			} else {
				probeIPProtocolGauge.Set(4)
			}
			return ip, 0.0, err
		}
	}

	if ip.IP.To4() == nil {
		probeIPProtocolGauge.Set(6)
	} else {
		probeIPProtocolGauge.Set(4)
	}

	level.Info(logger).Log("msg", "Resolved target address", "ip", ip)
	return ip, lookupTime, nil
}
