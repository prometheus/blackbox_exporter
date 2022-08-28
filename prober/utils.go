// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/prometheus/client_golang/prometheus"
)

// Returns the IP for the IPProtocol and lookup time.
func chooseProtocol(ctx context.Context, IPProtocol string, randomResolvedIP bool, fallbackIPProtocol bool, target string, registry *prometheus.Registry, logger log.Logger) (ip *net.IPAddr, lookupTime float64, err error) {
	probeDNSLookupTimeSeconds := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_lookup_time_seconds",
		Help: "Returns the time taken for probe dns lookup in seconds",
	})

	probeIPProtocolGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_protocol",
		Help: "Specifies whether probe ip protocol is IP4 or IP6",
	})

	probeIPAddrHash := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_addr_hash",
		Help: "Specifies the hash of IP address. It's useful to detect if the IP address changes.",
	})
	registry.MustRegister(probeIPProtocolGauge)
	registry.MustRegister(probeDNSLookupTimeSeconds)
	registry.MustRegister(probeIPAddrHash)

	var protocolVersion int
	var fallbackVersion int
	if IPProtocol == "ip6" || IPProtocol == "" {
		IPProtocol = "ip6"
		protocolVersion = 6
		fallbackVersion = 4
	} else {
		IPProtocol = "ip4"
		protocolVersion = 4
		fallbackVersion = 6
	}

	level.Info(logger).Log("msg", "Resolving target address", "target", target, "ip_protocol", IPProtocol)
	resolveStart := time.Now()

	defer func() {
		lookupTime = time.Since(resolveStart).Seconds()
		probeDNSLookupTimeSeconds.Add(lookupTime)
	}()

	resolver := &net.Resolver{}
	if !fallbackIPProtocol {
		ips, err := resolver.LookupIP(ctx, IPProtocol, target)
		if err == nil {
			ipAddr := getIP(ips, randomResolvedIP)
			if ipAddr != nil {
				level.Info(logger).Log("msg", "Resolved target address", "target", target, "ip", ipAddr.String())
				probeIPProtocolGauge.Set(float64(protocolVersion))
				probeIPAddrHash.Set(ipHash(*ipAddr))
				return &net.IPAddr{IP: *ipAddr}, lookupTime, nil
			}
		}
		// Unable to find IP and no fallback set.
		level.Error(logger).Log("msg", "Resolution with IP protocol failed", "target", target, "ip_protocol", IPProtocol, "err", err)
		return nil, 0.0, err
	}

	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		level.Error(logger).Log("msg", "Resolution with IP protocol failed", "target", target, "err", err)
		return nil, 0.0, err
	}

	protocol, addr := getIPAddr(ips, randomResolvedIP, protocolVersion, fallbackVersion)
	if addr == nil {
		return nil, 0.0, fmt.Errorf("unable to find ip; no fallback")
	}

	level.Info(logger).Log("msg", "Resolved target address", "target", target, "ip", addr.String())
	probeIPProtocolGauge.Set(float64(protocol))
	probeIPAddrHash.Set(ipHash(addr.IP))
	return addr, lookupTime, nil
}

func getIPAddr(ips []net.IPAddr, randomIndex bool, protocolVersion int, fallbackVersion int) (int, *net.IPAddr) {
	// Split the IPs by their protocol version.
	var maxIPs int
	if randomIndex {
		maxIPs = len(ips)
	} else {
		maxIPs = 1
	}
	ip4 := make([]net.IPAddr, 0, maxIPs)
	ip6 := make([]net.IPAddr, 0, maxIPs)

	var protocolIPs, fallbackIPs *[]net.IPAddr
	switch protocolVersion {
	case 4:
		protocolIPs = &ip4
		fallbackIPs = &ip6
	case 6:
		protocolIPs = &ip6
		fallbackIPs = &ip4
	}

	for _, ip := range ips {
		if ip.IP.To4() == nil {
			if randomIndex || len(ip6) == 0 {
				ip6 = append(ip6, ip)
			}
		} else {
			if randomIndex || len(ip4) == 0 {
				ip4 = append(ip4, ip)
			}
		}
		if !randomIndex {
			for _, ip := range *protocolIPs {
				// Found IP in the requested protocol, no need to check others, because the first IP is requested.
				return protocolVersion, &ip
			}
		}
	}

	if !randomIndex {
		for _, ip := range *fallbackIPs {
			return fallbackVersion, &ip
		}
	} else {
		ip := getRandomIPAddr(*protocolIPs)
		if ip != nil {
			return protocolVersion, ip
		}
		ip = getRandomIPAddr(*fallbackIPs)
		if ip != nil {
			return fallbackVersion, ip
		}
	}

	return protocolVersion, nil
}

func ipHash(ip net.IP) float64 {
	h := fnv.New32a()
	if ip.To4() != nil {
		h.Write(ip.To4())
	} else {
		h.Write(ip.To16())
	}
	return float64(h.Sum32())
}

func getIP(a []net.IP, randomIndex bool) *net.IP {
	size := len(a)
	if size == 0 {
		return nil
	}
	if size == 1 || !randomIndex {
		return &a[0]
	}
	return &a[rand.Intn(size)]
}

func getRandomIPAddr(a []net.IPAddr) *net.IPAddr {
	size := len(a)
	if size == 0 {
		return nil
	}
	if size == 1 {
		return &a[0]
	}
	return &a[rand.Intn(size)]
}
