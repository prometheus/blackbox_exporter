// Copyright 2015 The Prometheus Authors
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
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gjflsl/blackbox_exporter/config"
)

func TestTCPConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
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
	if !ProbeTCP(testCTX, ln.Addr().String(), config.Module{}, registry) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch
}

func TestTCPConnectionFails(t *testing.T) {
	// Invalid port number.
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ProbeTCP(testCTX, ":0", config.Module{}, registry) {
		t.Fatalf("TCP module suceeded, expected failure.")
	}
}

func TestTCPConnectionQueryResponseIRC(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	module := config.Module{
		TCP: config.TCPProbe{
			QueryResponse: []config.QueryResponse{
				{Send: "NICK prober"},
				{Send: "USER prober prober prober :prober"},
				{Expect: "^:[^ ]+ 001"},
			},
		},
	}

	ch := make(chan (struct{}))
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		fmt.Fprintf(conn, ":ircd.localhost NOTICE AUTH :*** Looking up your hostname...\n")
		var nick, user, mode, unused, realname string
		fmt.Fscanf(conn, "NICK %s", &nick)
		fmt.Fscanf(conn, "USER %s %s %s :%s", &user, &mode, &unused, &realname)
		fmt.Fprintf(conn, ":ircd.localhost 001 %s :Welcome to IRC!\n", nick)
		conn.Close()
		ch <- struct{}{}
	}()
	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		fmt.Fprintf(conn, ":ircd.localhost NOTICE AUTH :*** Looking up your hostname...\n")
		var nick, user, mode, unused, realname string
		fmt.Fscanf(conn, "NICK %s", &nick)
		fmt.Fscanf(conn, "USER %s %s %s :%s", &user, &mode, &unused, &realname)
		fmt.Fprintf(conn, "ERROR: Your IP address has been blacklisted.\n")
		conn.Close()
		ch <- struct{}{}
	}()
	registry = prometheus.NewRegistry()
	if ProbeTCP(testCTX, ln.Addr().String(), module, registry) {
		t.Fatalf("TCP module succeeded, expected failure.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_failed_due_to_regex": 1,
	}
	checkRegistryResults(expectedResults, mfs, t)
	<-ch
}

func TestTCPConnectionQueryResponseMatching(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	time.Sleep(time.Millisecond * 100)
	module := config.Module{
		TCP: config.TCPProbe{
			QueryResponse: []config.QueryResponse{
				{
					Expect: "SSH-2.0-(OpenSSH_6.9p1) Debian-2",
					Send:   "CONFIRM ${1}",
				},
			},
		},
	}

	ch := make(chan string)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(fmt.Sprintf("Error accepting on socket: %s", err))
		}
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		fmt.Fprintf(conn, "SSH-2.0-OpenSSH_6.9p1 Debian-2\n")
		var version string
		fmt.Fscanf(conn, "CONFIRM %s", &version)
		conn.Close()
		ch <- version
	}()
	registry := prometheus.NewRegistry()
	if !ProbeTCP(testCTX, ln.Addr().String(), module, registry) {
		t.Fatalf("TCP module failed, expected success.")
	}
	if got, want := <-ch, "OpenSSH_6.9p1"; got != want {
		t.Fatalf("Read unexpected version: got %q, want %q", got, want)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_failed_due_to_regex": 0,
	}
	checkRegistryResults(expectedResults, mfs, t)

}

func TestTCPConnectionProtocol(t *testing.T) {
	// This test assumes that listening TCP listens both IPv6 and IPv4 traffic and
	// localhost resolves to both 127.0.0.1 and ::1. we must skip the test if either
	// of these isn't true. This should be true for modern Linux systems.
	if runtime.GOOS == "dragonfly" || runtime.GOOS == "openbsd" {
		t.Skip("IPv6 socket isn't able to accept IPv4 traffic in the system.")
	}
	_, err := net.ResolveIPAddr("ip6", "localhost")
	if err != nil {
		t.Skip("\"localhost\" doesn't resolve to ::1.")
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Force IPv4
	module := config.Module{
		TCP: config.TCPProbe{
			PreferredIPProtocol: "ip4",
		},
	}

	registry := prometheus.NewRegistry()
	result := ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp4\" connection test failed, expected success.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := map[string]float64{
		"probe_ip_protocol": 4,
	}
	checkRegistryResults(expectedResults, mfs, t)

	// Force IPv6
	module = config.Module{
		TCP: config.TCPProbe{},
	}

	registry = prometheus.NewRegistry()
	result = ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp6\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults = map[string]float64{
		"probe_ip_protocol": 6,
	}
	checkRegistryResults(expectedResults, mfs, t)

	// Prefer IPv4
	module = config.Module{
		TCP: config.TCPProbe{
			PreferredIPProtocol: "ip4",
		},
	}

	registry = prometheus.NewRegistry()
	result = ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp\", prefer: \"ip4\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults = map[string]float64{
		"probe_ip_protocol": 4,
	}
	checkRegistryResults(expectedResults, mfs, t)

	// Prefer IPv6
	module = config.Module{
		TCP: config.TCPProbe{
			PreferredIPProtocol: "ip6",
		},
	}

	registry = prometheus.NewRegistry()
	result = ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp\", prefer: \"ip6\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults = map[string]float64{
		"probe_ip_protocol": 6,
	}
	checkRegistryResults(expectedResults, mfs, t)

	// Prefer nothing
	module = config.Module{
		TCP: config.TCPProbe{},
	}

	registry = prometheus.NewRegistry()
	result = ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults = map[string]float64{
		"probe_ip_protocol": 6,
	}
	checkRegistryResults(expectedResults, mfs, t)

	// No protocol
	module = config.Module{
		TCP: config.TCPProbe{},
	}

	registry = prometheus.NewRegistry()
	result = ProbeTCP(testCTX, net.JoinHostPort("localhost", port), module, registry)
	if !result {
		t.Fatalf("TCP connection test with protocol unspecified failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults = map[string]float64{
		"probe_ip_protocol": 6,
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestPrometheusTimeoutTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
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
	testCTX, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	if ProbeTCP(testCTX, ln.Addr().String(), config.Module{TCP: config.TCPProbe{
		QueryResponse: []config.QueryResponse{
			{
				Expect: "SSH-2.0-(OpenSSH_6.9p1) Debian-2",
			},
		},
	}}, registry) {
		t.Fatalf("TCP module succeeded, expected timeout failure.")
	}
	<-ch
}
