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
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestUnixConnection(t *testing.T) {
	// Create a temporary file for the socket.
	tmpfile, err := os.CreateTemp("", "unix-socket-test")
	if err != nil {
		t.Fatalf("Error creating temp file: %s", err)
	}
	socketPath := tmpfile.Name()
	// Close and remove the file so we can use the path for the socket.
	tmpfile.Close()
	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	ch := make(chan (struct{}))
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		conn.Close()
		ch <- struct{}{}
	}()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	if !ProbeUnix(testCTX, ln.Addr().String(), config.Module{Unix: config.UnixProbe{}}, registry, promslog.NewNopLogger()) {
		t.Fatalf("Unix module failed, expected success.")
	}
	<-ch
}

func TestUnixConnectionFails(t *testing.T) {
	// Non-existent socket.
	socketPath := "/tmp/non-existent-socket-for-blackbox-exporter-test"
	os.Remove(socketPath) // Ensure it doesn't exist

	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ProbeUnix(testCTX, socketPath, config.Module{Unix: config.UnixProbe{}}, registry, promslog.NewNopLogger()) {
		t.Fatalf("Unix module succeeded, expected failure.")
	}
}
