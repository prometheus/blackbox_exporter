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
	"net"
	"sync/atomic"

	"golang.org/x/net/ipv4"
)

// lastDF holds the DF bit of the last echo request, which the kernel answers on its own.
var lastDF atomic.Bool

func watchICMP(pc net.PacketConn) {
	c, err := ipv4.NewRawConn(pc)
	fatal(err)
	b := make([]byte, 65536)
	for {
		h, p, _, err := c.ReadFrom(b)
		fatal(err)
		if len(p) > 0 && p[0] == byte(ipv4.ICMPTypeEcho) {
			lastDF.Store(h.Flags&ipv4.DontFragment != 0)
		}
	}
}
