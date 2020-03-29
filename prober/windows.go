// Copyright 2020 The Prometheus Authors
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

// +build windows

package prober

import (
	"net"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
)

func setupDialer(dialProtocol, dialTarget string, module config.Module, logger log.Logger) (*net.Dialer, error) {
	var err error
	control := func(network, address string, c syscall.RawConn) error {
		var syscallErr error
		controlErr := c.Control(func(fd uintptr) {
			if module.TCP.TOS != 0 {
				level.Info(logger).Log("msg", "Setting TOS", "TOS", module.TCP.TOS)
				syscallErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TOS, module.TCP.TOS)
			}
		})
		if syscallErr != nil {
			level.Error(logger).Log("msg", "Could not set TOS", "err", syscallErr)
			err = syscallErr
			return syscallErr
		}
		if controlErr != nil {
			level.Error(logger).Log("msg", "Could not set TOS", "err", controlErr)
			err = controlErr
			return controlErr
		}
		return nil
	}

	if err != nil {
		return nil, err
	}
	return &net.Dialer{
		Control: control,
	}, nil
}
