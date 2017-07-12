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

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/log"
)

func dialTCP(ctx context.Context, target string, module Module, registry *prometheus.Registry) (net.Conn, error) {
	var dialProtocol, dialTarget string
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		log.Errorf("Error splitting target address and port: %v", err)
		return nil, err
	}

	ip, err := chooseProtocol(module.TCP.PreferredIPProtocol, targetAddress, registry)
	if err != nil {
		log.Errorf("Error choosing protocol: %v", err)
		return nil, err
	}

	if ip.IP.To4() == nil {
		dialProtocol = "tcp6"
	} else {
		dialProtocol = "tcp4"
	}
	dialTarget = net.JoinHostPort(ip.String(), port)

	if !module.TCP.TLS {
		return dialer.DialContext(ctx, dialProtocol, dialTarget)
	}
	tlsConfig, err := config.NewTLSConfig(&module.TCP.TLSConfig)
	if err != nil {
		log.Errorf("Error creating TLS configuration: %v", err)
		return nil, err
	}
	timeoutDeadline, _ := ctx.Deadline()
	dialer.Deadline = timeoutDeadline

	return tls.DialWithDialer(dialer, dialProtocol, dialTarget, tlsConfig)
}

func probeTCP(ctx context.Context, target string, module Module, registry *prometheus.Registry) bool {
	probeSSLEarliestCertExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: "Returns earliest SSL cert expiry date",
	})
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})
	registry.MustRegister(probeFailedDueToRegex)
	deadline := time.Now().Add(module.Timeout)
	conn, err := dialTCP(ctx, target, module, registry)
	if err != nil {
		log.Errorf("Error dialing TCP: %v", err)
		return false
	}
	defer conn.Close()

	// Set a deadline to prevent the following code from blocking forever.
	// If a deadline cannot be set, better fail the probe by returning an error
	// now rather than blocking forever.
	if err := conn.SetDeadline(deadline); err != nil {
		log.Errorf("Error setting deadline: %v", err)
		return false
	}
	if module.TCP.TLS {
		state := conn.(*tls.Conn).ConnectionState()
		registry.MustRegister(probeSSLEarliestCertExpiry)
		probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).UnixNano()) / 1e9)
	}
	scanner := bufio.NewScanner(conn)
	for _, qr := range module.TCP.QueryResponse {
		log.Debugf("Processing query response entry %+v", qr)
		send := qr.Send
		if qr.Expect != "" {
			re, err := regexp.Compile(qr.Expect)
			if err != nil {
				log.Errorf("Could not compile %q into regular expression: %v", qr.Expect, err)
				return false
			}
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				log.Debugf("read %q\n", scanner.Text())
				match = re.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					log.Debugf("regexp %q matched %q", re, scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				return false
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				return false
			}
			probeFailedDueToRegex.Set(0)
			send = string(re.Expand(nil, []byte(send), scanner.Bytes(), match))
		}
		if send != "" {
			log.Debugf("Sending %q", send)
			if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
				return false
			}
		}
	}
	return true
}
