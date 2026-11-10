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

//go:build unix

package prober

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/prometheus/blackbox_exporter/config"
)

// ecnMask covers the two ECN bits of the TOS byte. The kernel may set them
// on TCP sockets, so the tests only compare the other six bits.
const ecnMask = 0x03

// connTOS returns the IPv4 TOS byte, or the IPv6 traffic class, of a TCP or
// UDP connection.
func connTOS(t *testing.T, c net.Conn) int {
	t.Helper()
	var ip net.IP
	switch a := c.LocalAddr().(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		t.Fatalf("Unexpected local address type %T", a)
	}

	var (
		tos int
		err error
	)
	if ip.To4() == nil {
		tos, err = ipv6.NewConn(c).TrafficClass()
	} else {
		tos, err = ipv4.NewConn(c).TOS()
	}
	if err != nil {
		t.Fatalf("Error reading TOS: %s", err)
	}
	return tos
}

// tcpConnOf returns the *net.TCPConn under the TLS and go-conntrack wrappers
// that the HTTP client puts around a connection.
func tcpConnOf(t *testing.T, c net.Conn) *net.TCPConn {
	t.Helper()
	for {
		switch v := c.(type) {
		case *net.TCPConn:
			return v
		case *tls.Conn:
			c = v.NetConn()
		default:
			// go-conntrack embeds the connection it wraps and has no
			// method to return it.
			s := reflect.Indirect(reflect.ValueOf(c))
			if s.Kind() != reflect.Struct {
				t.Fatalf("Cannot unwrap connection of type %T", c)
			}
			f := s.FieldByName("Conn")
			if !f.IsValid() || !f.CanInterface() {
				t.Fatalf("Cannot unwrap connection of type %T", c)
			}
			inner, ok := reflect.TypeAssert[net.Conn](f)
			if !ok || inner == nil {
				t.Fatalf("Cannot unwrap connection of type %T", c)
			}
			c = inner
		}
	}
}

func TestTOSControl(t *testing.T) {
	const tos = 0xb8 // DSCP 46 (EF).

	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			listenAddr := "127.0.0.1:0"
			if strings.HasSuffix(network, "6") {
				listenAddr = "[::1]:0"
			}

			var target string
			if strings.HasPrefix(network, "tcp") {
				ln, err := net.Listen(network, listenAddr)
				if err != nil {
					t.Skipf("Cannot listen on %s: %s", listenAddr, err)
				}
				defer ln.Close()
				target = ln.Addr().String()
			} else {
				pc, err := net.ListenPacket(network, listenAddr)
				if err != nil {
					t.Skipf("Cannot listen on %s: %s", listenAddr, err)
				}
				defer pc.Close()
				target = pc.LocalAddr().String()
			}

			dialer := &net.Dialer{Control: tosControl(tos)}
			conn, err := dialer.Dial(network, target)
			if err != nil {
				t.Fatalf("Error dialing %s: %s", target, err)
			}
			defer conn.Close()

			if got := connTOS(t, conn); got&^ecnMask != tos {
				t.Errorf("Got tos %#x, want %#x", got, tos)
			}
		})
	}
}

func TestSetICMPTOS(t *testing.T) {
	const tos = 0x28 // DSCP 10 (AF11).

	tests := []struct {
		name         string
		unprivileged string
		privileged   string
		address      string
	}{
		{"ip4", "udp4", "ip4:icmp", "127.0.0.1"},
		{"ip6", "udp6", "ip6:ipv6-icmp", "::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Try an unprivileged socket first, as ProbeICMP does.
			c, err := icmp.ListenPacket(test.unprivileged, test.address)
			if err != nil {
				c, err = icmp.ListenPacket(test.privileged, test.address)
			}
			if err != nil {
				t.Skipf("Cannot open an ICMP socket: %s", err)
			}
			defer c.Close()

			if err := setICMPTOS(c, tos); err != nil {
				t.Fatalf("Error setting tos: %s", err)
			}

			var got int
			if p := c.IPv4PacketConn(); p != nil {
				got, err = p.TOS()
			} else {
				got, err = c.IPv6PacketConn().TrafficClass()
			}
			if err != nil {
				t.Fatalf("Error reading tos: %s", err)
			}
			if got != tos {
				t.Errorf("Got tos %#x, want %#x", got, tos)
			}
		})
	}
}

func TestICMPTOS(t *testing.T) {
	const tos = 0x28 // DSCP 10 (AF11).

	// A second ICMP socket on [::1] reads the traffic class of the echo
	// request the probe sends. golang.org/x/net/ipv4 cannot report the TOS
	// byte of a received packet, so this test uses IPv6 only.
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::1")
	if err != nil {
		c, err = icmp.ListenPacket("udp6", "::1")
	}
	if err != nil {
		t.Skipf("Cannot open an ICMP socket on [::1]: %s", err)
	}
	defer c.Close()
	p := c.IPv6PacketConn()
	if err := p.SetControlMessage(ipv6.FlagTrafficClass, true); err != nil {
		t.Skipf("Cannot read the traffic class of received packets: %s", err)
	}

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	module := config.Module{Timeout: time.Second, ICMP: config.ICMPProbe{IPProtocol: "ip6", TOS: tos}}
	if !ProbeICMP(testCTX, "::1", module, prometheus.NewRegistry(), promslog.NewNopLogger()) {
		t.Fatal("ICMP probe failed, expected success.")
	}

	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("Error setting read deadline: %s", err)
	}
	buf := make([]byte, 1500)
	for {
		n, cm, _, err := p.ReadFrom(buf)
		if err != nil {
			// On Linux, unprivileged ICMP sockets only get echo replies,
			// so only a raw socket sees the echo request.
			t.Skipf("Did not receive the echo request of the probe: %s", err)
		}
		m, err := icmp.ParseMessage(ipv6.ICMPTypeEchoRequest.Protocol(), buf[:n])
		if err != nil || m.Type != ipv6.ICMPTypeEchoRequest {
			continue
		}
		if echo, ok := m.Body.(*icmp.Echo); !ok || string(echo.Data) != "Prometheus Blackbox Exporter" {
			continue
		}
		if cm == nil {
			t.Fatal("Got no control message with the echo request.")
		}
		if cm.TrafficClass != tos {
			t.Errorf("Got traffic class %#x, want %#x", cm.TrafficClass, tos)
		}
		return
	}
}

func TestTCPTOS(t *testing.T) {
	const tos = 0x28 // DSCP 10 (AF11).

	tests := []struct {
		ipProtocol string
		listenAddr string
	}{
		{"ip4", "127.0.0.1:0"},
		{"ip6", "[::1]:0"},
	}
	for _, test := range tests {
		t.Run(test.ipProtocol, func(t *testing.T) {
			ln, err := net.Listen("tcp", test.listenAddr)
			if err != nil {
				t.Skipf("Cannot listen on %s: %s", test.listenAddr, err)
			}
			defer ln.Close()

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			module := config.Module{TCP: config.TCPProbe{IPProtocol: test.ipProtocol, TOS: tos}}
			conn, err := dialTCP(testCTX, ln.Addr().String(), module, prometheus.NewRegistry(), promslog.NewNopLogger())
			if err != nil {
				t.Fatalf("Error dialing TCP: %s", err)
			}
			defer conn.Close()

			if got := connTOS(t, conn); got&^ecnMask != tos {
				t.Errorf("Got tos %#x, want %#x", got, tos)
			}
		})
	}
}

func TestDNSTOS(t *testing.T) {
	const tos = 0x28 // DSCP 10 (AF11).

	// The server reads the traffic class of the query from an IPv6 control
	// message. golang.org/x/net/ipv4 cannot report the TOS byte of a
	// received packet, so this test uses IPv6 only.
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("Cannot listen on [::1]: %s", err)
	}
	defer pc.Close()
	p := ipv6.NewPacketConn(pc)
	if err := p.SetControlMessage(ipv6.FlagTrafficClass, true); err != nil {
		t.Skipf("Cannot read the traffic class of received packets: %s", err)
	}

	gotTOS := make(chan int, 1)
	go func() {
		buf := make([]byte, 512)
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			gotTOS <- -1
			return
		}
		if cm == nil {
			gotTOS <- -1
		} else {
			gotTOS <- cm.TrafficClass
		}
		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		out, err := resp.Pack()
		if err != nil {
			return
		}
		p.WriteTo(out, nil, src)
	}()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	module := config.Module{
		Timeout: time.Second,
		DNS: config.DNSProbe{
			IPProtocol: "ip6",
			QueryName:  "example.com",
			TOS:        tos,
		},
	}
	if !ProbeDNS(testCTX, pc.LocalAddr().String(), module, prometheus.NewRegistry(), promslog.NewNopLogger()) {
		t.Fatal("DNS probe failed, expected success.")
	}
	if got := <-gotTOS; got != tos {
		t.Errorf("Got traffic class %#x, want %#x", got, tos)
	}
}

func TestHTTPTOS(t *testing.T) {
	const tos = 0x28 // DSCP 10 (AF11).

	okHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	ts := httptest.NewServer(okHandler)
	defer ts.Close()
	tlsTS := httptest.NewTLSServer(okHandler)
	defer tlsTS.Close()
	// A redirect to another host goes through the transport that does not
	// set the TLS ServerName.
	redirectTS := httptest.NewServer(http.RedirectHandler(ts.URL, http.StatusFound))
	defer redirectTS.Close()

	tests := []struct {
		name      string
		target    string
		wantConns int
	}{
		{"http", ts.URL, 1},
		{"https", tlsTS.URL, 1},
		{"redirect to another host", redirectTS.URL, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// ProbeHTTP adds its own trace to the request context. The hooks
			// set here still run, so they see each connection of the probe.
			var got []int
			trace := &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) {
					got = append(got, connTOS(t, tcpConnOf(t, info.Conn)))
				},
			}
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			testCTX = httptrace.WithClientTrace(testCTX, trace)

			module := config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{
				IPProtocolFallback: true,
				TOS:                tos,
				HTTPClientConfig: pconfig.HTTPClientConfig{
					FollowRedirects: true,
					TLSConfig:       pconfig.TLSConfig{InsecureSkipVerify: true},
				},
			}}
			if !ProbeHTTP(testCTX, test.target, module, prometheus.NewRegistry(), promslog.NewNopLogger()) {
				t.Fatal("HTTP probe failed, expected success.")
			}
			if len(got) != test.wantConns {
				t.Fatalf("Got %d connections, want %d", len(got), test.wantConns)
			}
			for i, g := range got {
				if g&^ecnMask != tos {
					t.Errorf("Connection %d: got tos %#x, want %#x", i, g, tos)
				}
			}
		})
	}
}
