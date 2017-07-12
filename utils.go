package main

import (
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Returns the preferedIPProtocol, the dialProtocol, and sets the probeIPProtocolGauge.
func chooseProtocol(preferredIPProtocol string, target string, registry *prometheus.Registry) (*net.IPAddr, error) {
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

	if preferredIPProtocol == "ip6" || preferredIPProtocol == "" {
		preferredIPProtocol = "ip6"
		fallbackProtocol = "ip4"
	} else {
		preferredIPProtocol = "ip4"
		fallbackProtocol = "ip6"
	}

	if preferredIPProtocol == "ip6" {
		fallbackProtocol = "ip4"
	} else {
		fallbackProtocol = "ip6"
	}

	resolveStart := time.Now()

	defer probeDNSLookupTimeSeconds.Add(time.Since(resolveStart).Seconds())

	ip, err := net.ResolveIPAddr(preferredIPProtocol, target)
	if err != nil {
		ip, err = net.ResolveIPAddr(fallbackProtocol, target)
		if err != nil {
			return ip, err
		}
	}

	if ip.IP.To4() == nil {
		probeIPProtocolGauge.Set(6)
	} else {
		probeIPProtocolGauge.Set(4)
	}

	return ip, nil

}
