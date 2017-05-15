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

package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http/httptest"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
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
			t.Fatalf("Error accepting on socket: %s", err)
		}
		conn.Close()
		ch <- struct{}{}
	}()
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	if !probeTCP(ln.Addr().String(), recorder, Module{Timeout: time.Second}, registry) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch
}

func TestTCPConnectionFails(t *testing.T) {
	// Invalid port number.
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	if probeTCP(":0", recorder, Module{Timeout: time.Second}, registry) {
		t.Fatalf("TCP module suceeded, expected failure.")
	}
}

func TestTCPConnectionQueryResponseIRC(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	module := Module{
		Timeout: time.Second,
		TCP: TCPProbe{
			QueryResponse: []QueryResponse{
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
			t.Fatalf("Error accepting on socket: %s", err)
		}
		fmt.Fprintf(conn, ":ircd.localhost NOTICE AUTH :*** Looking up your hostname...\n")
		var nick, user, mode, unused, realname string
		fmt.Fscanf(conn, "NICK %s", &nick)
		fmt.Fscanf(conn, "USER %s %s %s :%s", &user, &mode, &unused, &realname)
		fmt.Fprintf(conn, ":ircd.localhost 001 %s :Welcome to IRC!\n", nick)
		conn.Close()
		ch <- struct{}{}
	}()
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	if !probeTCP(ln.Addr().String(), recorder, module, registry) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatalf("Error accepting on socket: %s", err)
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
	if probeTCP(ln.Addr().String(), recorder, module, registry) {
		t.Fatalf("TCP module succeeded, expected failure.")
	}
	<-ch
}

func TestTCPConnectionQueryResponseMatching(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	defer ln.Close()

	module := Module{
		Timeout: time.Second,
		TCP: TCPProbe{
			QueryResponse: []QueryResponse{
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
			t.Fatalf("Error accepting on socket: %s", err)
		}
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		fmt.Fprintf(conn, "SSH-2.0-OpenSSH_6.9p1 Debian-2\n")
		var version string
		fmt.Fscanf(conn, "CONFIRM %s", &version)
		conn.Close()
		ch <- version
	}()
	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	if !probeTCP(ln.Addr().String(), recorder, module, registry) {
		t.Fatalf("TCP module failed, expected success.")
	}
	if got, want := <-ch, "OpenSSH_6.9p1"; got != want {
		t.Fatalf("Read unexpected version: got %q, want %q", got, want)
	}
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

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Force IPv4
	module := Module{
		Timeout: time.Second,
		TCP: TCPProbe{
			Protocol: "tcp4",
		},
	}

	recorder := httptest.NewRecorder()
	registry := prometheus.NewRegistry()
	result := probeTCP(net.JoinHostPort("localhost", port), recorder, module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp4\" connection test failed, expected success.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for _, mf := range mfs {
		if _, err = expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re := regexp.MustCompile("probe_ip_protocol 4")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected IPv4, got %s", buf.String())
	}

	// Force IPv6
	module = Module{
		Timeout: time.Second,
		TCP: TCPProbe{
			Protocol: "tcp6",
		},
	}

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = probeTCP(net.JoinHostPort("localhost", port), recorder, module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp6\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if _, err = expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	regexp.MustCompile("probe_ip_protocol 6")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected IPv6, got %s", buf.String())
	}

	// Prefer IPv4
	module = Module{
		Timeout: time.Second,
		TCP: TCPProbe{
			Protocol:            "tcp",
			PreferredIPProtocol: "ip4",
		},
	}

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = probeTCP(net.JoinHostPort("localhost", port), recorder, module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp\", prefer: \"ip4\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if _, err = expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re = regexp.MustCompile("probe_ip_protocol 4")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected IPv4, got %s", buf.String())
	}

	// Prefer IPv6
	module = Module{
		Timeout: time.Second,
		TCP: TCPProbe{
			Protocol:            "tcp",
			PreferredIPProtocol: "ip6",
		},
	}

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = probeTCP(net.JoinHostPort("localhost", port), recorder, module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp\", prefer: \"ip6\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if _, err = expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re = regexp.MustCompile("probe_ip_protocol 6")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected IPv6, got %s", buf.String())
	}

	// Prefer nothing
	module = Module{
		Timeout: time.Second,
		TCP: TCPProbe{
			Protocol: "tcp",
		},
	}

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = probeTCP(net.JoinHostPort("localhost", port), recorder, module, registry)
	if !result {
		t.Fatalf("TCP protocol: \"tcp\" connection test failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if _, err = expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re = regexp.MustCompile("probe_ip_protocol 6")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected IPv6, got %s", buf.String())
	}

	// No protocol
	module = Module{
		Timeout: time.Second,
		TCP:     TCPProbe{},
	}

	recorder = httptest.NewRecorder()
	registry = prometheus.NewRegistry()
	result = probeTCP(net.JoinHostPort("localhost", port), recorder, module, registry)
	if !result {
		t.Fatalf("TCP connection test with protocol unspecified failed, expected success.")
	}
	mfs, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if _, err = expfmt.MetricFamilyToText(&buf, mf); err != nil {
			t.Fatal(err)
		}
	}
	re = regexp.MustCompile("probe_ip_protocol 6")
	if !re.Match(buf.Bytes()) {
		t.Errorf("Expected IPv6, got %s", buf.String())
	}
}
