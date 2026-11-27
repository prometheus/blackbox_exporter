// Copyright The Prometheus Authors
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
	"log"
	"net"
)

func main() {
	dnsL, err := net.ListenPacket("udp", ":30053")
	fatal(err)
	grpcL := listen(net.JoinHostPort(ipv6Addr(), "30051"))
	// Last, because the compose health check waits for this port.
	httpL := listen(":30080")

	go serveHTTP(httpL)
	go serveDNS(dnsL)
	go serveGRPC(grpcL)
	log.Print("testserver ready")
	select {}
}

// ipv6Addr looks the address up, because Docker picks the subnet.
func ipv6Addr() string {
	addrs, err := net.InterfaceAddrs()
	fatal(err)
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil && n.IP.IsGlobalUnicast() {
			return n.IP.String()
		}
	}
	log.Fatal("no global IPv6 address, the compose network needs enable_ipv6")
	return ""
}

func listen(addr string) net.Listener {
	l, err := net.Listen("tcp", addr)
	fatal(err)
	return l
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
