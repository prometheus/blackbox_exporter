// Copyright 2025 The Prometheus Authors
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

//go:build linux

package prober

import (
	pconfig "github.com/prometheus/common/config"
	"log/slog"
	"net"
	"syscall"
)

func BindToInterface(options []pconfig.HTTPClientOption, sourceInterface string, _ *slog.Logger) []pconfig.HTTPClientOption {
	return append(options,
		pconfig.WithDialContextFunc((&net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				var err error
				c.Control(func(fd uintptr) {
					err = syscall.SetsockoptString(
						int(fd),
						syscall.SOL_SOCKET,
						syscall.SO_BINDTODEVICE,
						sourceInterface,
					)
				})
				return err
			},
		}).DialContext))
}
