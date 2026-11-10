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
	"bufio"
	"bytes"
	"log/slog"
	"testing"

	"github.com/prometheus/blackbox_exporter/config"
)

func TestReadUntilRegexpMatchIRC(t *testing.T) {
	re := config.MustNewRegexp("^:[^ ]+ 001")
	logger := slog.New(slog.DiscardHandler)

	input := ":ircd.localhost NOTICE AUTH :*** Looking up your hostname...\nERROR: Your IP address has been blacklisted.\n"
	reader := bufio.NewReader(bytes.NewReader([]byte(input)))

	_, match, err := readUntilRegexpMatch(reader, re, logger)
	if match != nil {
		t.Fatalf("expected no match, got match on error input")
	}
	if err != nil {
		t.Fatalf("expected nil error on EOF, got %v", err)
	}
}

func TestReadUntilRegexpMatchNoNewline(t *testing.T) {
	re := config.MustNewRegexp("^SSH-2.0-")
	logger := slog.New(slog.DiscardHandler)

	input := "SSH-2.0-OpenSSH_6.9p1"
	reader := bufio.NewReader(bytes.NewReader([]byte(input)))

	line, match, err := readUntilRegexpMatch(reader, re, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match == nil {
		t.Fatal("expected match")
	}
	if string(line) != input {
		t.Fatalf("got line %q, want %q", line, input)
	}
}
