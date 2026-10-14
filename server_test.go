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

package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// TestServerReadHeaderTimeout verifies that the server built by newServer closes
// a connection whose request headers never complete — i.e. ReadHeaderTimeout is
// set and effective. Without it, such a connection would be held open
// indefinitely (a Slowloris vector). A well-formed request must still succeed.
func TestServerReadHeaderTimeout(t *testing.T) {
	// Shorten the production timeout for the test; newServer reads this var.
	orig := serverReadHeaderTimeout
	serverReadHeaderTimeout = 250 * time.Millisecond
	t.Cleanup(func() { serverReadHeaderTimeout = orig })

	srv := newServer()
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Sanity: a well-formed request still succeeds.
	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("well-formed request failed: %v", err)
	}
	_ = resp.Body.Close()

	// A client that starts the request headers but never terminates them (no
	// final CRLF), holding the connection open.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n")); err != nil {
		t.Fatalf("write partial request: %v", err)
	}

	// The server must close the connection once ReadHeaderTimeout elapses. Read
	// in a goroutine so the test never hangs if the timeout is not enforced.
	done := make(chan struct{})
	go func() {
		_, _ = conn.Read(make([]byte, 1)) // returns on server close (EOF or 408)
		close(done)
	}()

	select {
	case <-done:
		// Server closed the stalled connection: ReadHeaderTimeout is effective.
	case <-time.After(5 * time.Second):
		t.Fatal("server did not close the stalled connection within 5s; ReadHeaderTimeout not effective")
	}
}
