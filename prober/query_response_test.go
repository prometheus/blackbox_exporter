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
