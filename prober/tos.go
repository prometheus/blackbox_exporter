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

package prober

import (
	"fmt"
	"syscall"

	"golang.org/x/net/icmp"
)

// tosControl returns a net.Dialer Control function that sets the IPv4 TOS
// byte, or the IPv6 traffic class, to tos before the socket connects. This
// way the first packet (for example the TCP SYN) already carries the value.
func tosControl(tos int) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = setSockoptTOS(fd, network, tos)
		}); err != nil {
			return err
		}
		if sockErr != nil {
			return fmt.Errorf("setting tos %#x: %w", tos, sockErr)
		}
		return nil
	}
}

// setICMPTOS sets the IPv4 TOS byte, or the IPv6 traffic class, on an ICMP
// socket.
func setICMPTOS(c *icmp.PacketConn, tos int) error {
	if p := c.IPv4PacketConn(); p != nil {
		return p.SetTOS(tos)
	}
	return c.IPv6PacketConn().SetTrafficClass(tos)
}
