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
	"fmt"
	"net"
	"testing"
	"time"
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
	if !probeTCP(ln.Addr().String(), nil, Module{Timeout: time.Second}) {
		t.Fatalf("TCP module failed, expected success.")
	}
	<-ch
}

func TestTCPConnectionFails(t *testing.T) {
	// Invalid port number.
	if probeTCP(":0", nil, Module{Timeout: time.Second}) {
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
				QueryResponse{Send: "NICK prober"},
				QueryResponse{Send: "USER prober prober prober :prober"},
				QueryResponse{Expect: "^:[^ ]+ 001"},
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
	if !probeTCP(ln.Addr().String(), nil, module) {
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
	if probeTCP(ln.Addr().String(), nil, module) {
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
				QueryResponse{
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
	if !probeTCP(ln.Addr().String(), nil, module) {
		t.Fatalf("TCP module failed, expected success.")
	}
	if got, want := <-ch, "OpenSSH_6.9p1"; got != want {
		t.Fatalf("Read unexpected version: got %q, want %q", got, want)
	}
}
