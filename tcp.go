package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/prometheus/log"
)

func dialTCP(target string, module Module) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: module.Timeout}
	if !module.TCP.TLS {
		return dialer.Dial("tcp", target)
	}
	config, err := module.TCP.TLSConfig.GenerateConfig()
	if err != nil {
		return nil, err
	}
	return tls.DialWithDialer(dialer, "tcp", target, config)
}

func probeTCP(target string, w http.ResponseWriter, module Module, params url.Values) bool {
	deadline := time.Now().Add(module.Timeout)
	conn, err := dialTCP(target, module)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set a deadline to prevent the following code from blocking forever.
	// If a deadline cannot be set, better fail the probe by returning an error
	// now rather than blocking forever.
	if err := conn.SetDeadline(deadline); err != nil {
		return false
	}
	if module.TCP.TLS {
		state := conn.(*tls.Conn).ConnectionState()
		fmt.Fprintf(w, "probe_ssl_earliest_cert_expiry %f\n",
			float64(getEarliestCertExpiry(&state).UnixNano())/1e9)
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
				return false
			}
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
