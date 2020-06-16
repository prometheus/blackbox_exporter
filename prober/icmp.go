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
	"bytes"
	"context"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/prometheus/blackbox_exporter/config"
)

var (
	icmpID            int
	icmpSequence      uint16
	icmpSequenceMutex sync.Mutex
)

func init() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// PID is typically 1 when running in a container; in that case, set
	// the ICMP echo ID to a random value to avoid potential clashes with
	// other blackbox_exporter instances. See #411.
	if pid := os.Getpid(); pid == 1 {
		icmpID = r.Intn(1 << 16)
	} else {
		icmpID = pid & 0xffff
	}

	// Start the ICMP echo sequence at a random offset to prevent them from
	// being in sync when several blackbox_exporter instances are restarted
	// at the same time. See #411.
	icmpSequence = uint16(r.Intn(1 << 16))
}

func getICMPSequence() uint16 {
	icmpSequenceMutex.Lock()
	defer icmpSequenceMutex.Unlock()
	icmpSequence++
	return icmpSequence
}

func ProbeICMP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var (
		socket      net.PacketConn
		requestType icmp.Type
		replyType   icmp.Type

		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_icmp_duration_seconds",
			Help: "Duration of icmp request by phase",
		}, []string{"phase"})
	)

	for _, lv := range []string{"resolve", "setup", "rtt"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)

	ip, lookupTime, err := chooseProtocol(ctx, module.ICMP.IPProtocol, module.ICMP.IPProtocolFallback, target, registry, logger)
	if err != nil {
		level.Warn(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)

	var srcIP net.IP
	if len(module.ICMP.SourceIPAddress) > 0 {
		if srcIP = net.ParseIP(module.ICMP.SourceIPAddress); srcIP == nil {
			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", module.ICMP.SourceIPAddress)
			return false
		}
		level.Info(logger).Log("msg", "Using source address", "srcIP", srcIP)
	}

	setupStart := time.Now()
	level.Info(logger).Log("msg", "Creating socket")

	unprivileged := false
	// Unprivileged sockets are supported on Darwin and Linux only.
	tryUnprivileged := runtime.GOOS == "darwin" || runtime.GOOS == "linux"

	if ip.IP.To4() == nil {
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply

		if srcIP == nil {
			srcIP = net.ParseIP("::")
		}

		var icmpConn *icmp.PacketConn
		if tryUnprivileged {
			// "udp" here means unprivileged -- not the protocol "udp".
			icmpConn, err = icmp.ListenPacket("udp6", srcIP.String())
			if err != nil {
				level.Debug(logger).Log("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
			} else {
				unprivileged = true
			}
		}

		if !unprivileged {
			icmpConn, err = icmp.ListenPacket("ip6:ipv6-icmp", srcIP.String())
			if err != nil {
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				return
			}
		}

		socket = icmpConn
	} else {
		requestType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply

		if srcIP == nil {
			srcIP = net.ParseIP("0.0.0.0")
		}

		var icmpConn *icmp.PacketConn
		if tryUnprivileged && !module.ICMP.DontFragment {
			icmpConn, err = icmp.ListenPacket("udp4", srcIP.String())
			if err != nil {
				level.Debug(logger).Log("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
			} else {
				unprivileged = true
			}
		}

		if !unprivileged {
			icmpConn, err = icmp.ListenPacket("ip4:icmp", srcIP.String())
			if err != nil {
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				return
			}
		}

		if module.ICMP.DontFragment {
			rc, err := ipv4.NewRawConn(icmpConn)
			if err != nil {
				level.Error(logger).Log("msg", "Error creating raw connection", "err", err)
				return
			}
			socket = &v4Conn{c: rc, df: true}
		} else {
			socket = icmpConn
		}
	}

	defer socket.Close()

	var dst net.Addr = ip
	if unprivileged {
		dst = &net.UDPAddr{IP: ip.IP, Zone: ip.Zone}
	}

	var data []byte
	if module.ICMP.PayloadSize != 0 {
		data = make([]byte, module.ICMP.PayloadSize)
		copy(data, "Prometheus Blackbox Exporter")
	} else {
		data = []byte("Prometheus Blackbox Exporter")
	}

	body := &icmp.Echo{
		ID:   icmpID,
		Seq:  int(getICMPSequence()),
		Data: data,
	}
	level.Info(logger).Log("msg", "Creating ICMP packet", "seq", body.Seq, "id", body.ID)
	wm := icmp.Message{
		Type: requestType,
		Code: 0,
		Body: body,
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
		return
	}

	durationGaugeVec.WithLabelValues("setup").Add(time.Since(setupStart).Seconds())
	level.Info(logger).Log("msg", "Writing out packet")
	rttStart := time.Now()
	if _, err = socket.WriteTo(wb, dst); err != nil {
		level.Warn(logger).Log("msg", "Error writing to socket", "err", err)
		return
	}

	// Reply should be the same except for the message type and ID if the kernel
	// used its own.
	wm.Type = replyType
	// Unprivileged cannot set IDs on Linux.
	idUnknown := unprivileged && runtime.GOOS == "linux"
	if idUnknown {
		body.ID = 0
	}
	wb, err = wm.Marshal(nil)
	if err != nil {
		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
		return
	}

	if idUnknown {
		// If the ID is unknown we also cannot know the checksum in userspace.
		wb[2] = 0
		wb[3] = 0
	}

	rb := make([]byte, 65536)
	deadline, _ := ctx.Deadline()
	if err := socket.SetReadDeadline(deadline); err != nil {
		level.Error(logger).Log("msg", "Error setting socket deadline", "err", err)
		return
	}
	level.Info(logger).Log("msg", "Waiting for reply packets")
	for {
		n, peer, err := socket.ReadFrom(rb)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				level.Warn(logger).Log("msg", "Timeout reading from socket", "err", err)
				return
			}
			level.Error(logger).Log("msg", "Error reading from socket", "err", err)
			continue
		}
		if peer.String() != dst.String() {
			continue
		}
		if idUnknown {
			// Clear the ID from the packet, as the kernel will have replaced it (and
			// kept track of our packet for us, hence clearing is safe).
			rb[4] = 0
			rb[5] = 0
		}
		if idUnknown || replyType == ipv6.ICMPTypeEchoReply {
			// Clear checksum to make comparison succeed.
			rb[2] = 0
			rb[3] = 0
		}
		if bytes.Equal(rb[:n], wb) {
			durationGaugeVec.WithLabelValues("rtt").Add(time.Since(rttStart).Seconds())
			level.Info(logger).Log("msg", "Found matching reply packet")
			return true
		}
	}
}

type v4Conn struct {
	c *ipv4.RawConn

	df  bool
	src net.IP
}

func (c *v4Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	h, p, _, err := c.c.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	copy(b, p)
	n := len(b)
	if len(p) < len(b) {
		n = len(p)
	}
	return n, &net.IPAddr{IP: h.Src}, nil
}

func (d *v4Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ipAddr, err := net.ResolveIPAddr(addr.Network(), addr.String())
	if err != nil {
		return 0, err
	}

	header := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		Protocol: 1,
		TotalLen: ipv4.HeaderLen + len(b),
		TTL:      64,
		Dst:      ipAddr.IP,
		Src:      d.src,
	}

	if d.df {
		header.Flags |= ipv4.DontFragment
	}

	return len(b), d.c.WriteTo(header, b, nil)
}

func (d *v4Conn) Close() error {
	return d.c.Close()
}

func (d *v4Conn) LocalAddr() net.Addr {
	return nil
}

func (d *v4Conn) SetDeadline(t time.Time) error {
	return d.c.SetDeadline(t)
}

func (d *v4Conn) SetReadDeadline(t time.Time) error {
	return d.c.SetReadDeadline(t)
}

func (d *v4Conn) SetWriteDeadline(t time.Time) error {
	return d.c.SetWriteDeadline(t)
}
