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
	"net"
	"os"
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
	icmpSequence      uint16
	icmpSequenceMutex sync.Mutex
)

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
	)
	timeoutDeadline, _ := ctx.Deadline()
	deadline := time.Now().Add(timeoutDeadline.Sub(time.Now()))

	ip, err := chooseProtocol(module.ICMP.PreferredIPProtocol, target, registry, logger)
	if err != nil {
		level.Warn(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}

	level.Info(logger).Log("msg", "Creating socket")
	if ip.IP.To4() == nil {
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply

		socket, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			level.Error(logger).Log("msg", "Error listening to socket", "err", err)
			return
		}
	} else {
		requestType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply

		if !module.ICMP.DontFragment {
			socket, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				return
			}
		} else {
			s, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				return
			}

			rc, err := ipv4.NewRawConn(s)
			if err != nil {
				level.Error(logger).Log("msg", "cannot construct raw connection", "err", err)
				return
			}
			socket = &dfConn{c: rc}
		}
	}

	defer socket.Close()

	var data []byte
	if module.ICMP.PayloadSize != 0 {
		data = make([]byte, module.ICMP.PayloadSize)
		copy(data, "Prometheus Blackbox Exporter")
	} else {
		data = []byte("Prometheus Blackbox Exporter")
	}

	body := &icmp.Echo{
		ID:   os.Getpid() & 0xffff,
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
	level.Info(logger).Log("msg", "Writing out packet")
	if _, err = socket.WriteTo(wb, ip); err != nil {
		level.Warn(logger).Log("msg", "Error writing to socket", "err", err)
		return
	}

	// Reply should be the same except for the message type.
	wm.Type = replyType
	wb, err = wm.Marshal(nil)
	if err != nil {
		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
		return
	}

	rb := make([]byte, 65536)
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
		if peer.String() != ip.String() {
			continue
		}
		if replyType == ipv6.ICMPTypeEchoReply {
			// Clear checksum to make comparison succeed.
			rb[2] = 0
			rb[3] = 0
		}
		if bytes.Compare(rb[:n], wb) == 0 {
			level.Info(logger).Log("msg", "Found matching reply packet")
			return true
		}
	}
}

type dfConn struct {
	c *ipv4.RawConn
}

func (c *dfConn) ReadFrom(b []byte) (int, net.Addr, error) {
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

func (d *dfConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ipAddr, err := net.ResolveIPAddr(addr.Network(), addr.String())
	if err != nil {
		return 0, err
	}

	dfHeader := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		Protocol: 1,
		TotalLen: ipv4.HeaderLen + len(b),
		Flags:    ipv4.DontFragment,
		TTL:      64,
		Dst:      ipAddr.IP,
	}

	return len(b), d.c.WriteTo(dfHeader, b, nil)
}

func (d *dfConn) Close() error {
	return d.c.Close()
}

func (d *dfConn) LocalAddr() net.Addr {
	return nil
}

func (d *dfConn) SetDeadline(t time.Time) error {
	return d.c.SetDeadline(t)
}

func (d *dfConn) SetReadDeadline(t time.Time) error {
	return d.c.SetReadDeadline(t)
}

func (d *dfConn) SetWriteDeadline(t time.Time) error {
	return d.c.SetWriteDeadline(t)
}
