// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package prober

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bbconfig "github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestRuntimeCollectsProbeMetrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := testRuntimeConfig(server.URL)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	runtime, err := NewRuntime(cfg, discardRuntimeLogger())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Shutdown(context.Background())

	registry := prometheus.NewRegistry()
	for _, c := range runtime.Collectors() {
		if err := registry.Register(c); err != nil {
			t.Fatalf("Register() error = %v", err)
		}
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	success := findRuntimeMetric(t, families, "probe_success")
	if got := success.GetGauge().GetValue(); got != 1 {
		t.Fatalf("probe_success = %v; want 1", got)
	}
	wantLabels := map[string]string{
		"target":      server.URL,
		"module":      "http_2xx",
		"target_name": "example",
		"environment": "test",
	}
	for name, want := range wantLabels {
		if got := runtimeLabelValue(success, name); got != want {
			t.Errorf("label %q = %q; want %q", name, got, want)
		}
	}
}

func TestRuntimeProbeTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	cfg := testRuntimeConfig(server.URL)
	cfg.MaxTimeout = 100 * time.Millisecond
	cfg.ProbeTimeoutOffset = 20 * time.Millisecond
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	runtime, err := NewRuntime(cfg, discardRuntimeLogger())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Shutdown(context.Background())

	registry := prometheus.NewRegistry()
	registry.MustRegister(runtime.Collectors()...)
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	if got := findRuntimeMetric(t, families, "probe_success").GetGauge().GetValue(); got != 0 {
		t.Fatalf("probe_success = %v; want 0", got)
	}
	if got := findRuntimeMetric(t, families, "probe_timeout_seconds").GetGauge().GetValue(); got != 0.08 {
		t.Fatalf("probe_timeout_seconds = %v; want 0.08", got)
	}
}

func TestRuntimeDistinguishesTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := testRuntimeConfig(server.URL)
	cfg.Targets = append(cfg.Targets, bbconfig.Target{
		Name:    "second",
		Address: server.URL,
		Module:  "http_2xx",
	})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	runtime, err := NewRuntime(cfg, discardRuntimeLogger())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Shutdown(context.Background())

	registry := prometheus.NewRegistry()
	registry.MustRegister(runtime.Collectors()...)
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, family := range families {
		if family.GetName() == "probe_success" {
			if got := len(family.Metric); got != 2 {
				t.Fatalf("probe_success series = %d; want 2", got)
			}
			return
		}
	}
	t.Fatal("probe_success metric not found")
}

func TestRuntimeShutdownCancelsProbe(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer server.Close()

	cfg := testRuntimeConfig(server.URL)
	cfg.MaxTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	runtime, err := NewRuntime(cfg, discardRuntimeLogger())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(runtime.Collectors()...)
	gatherDone := make(chan struct{})
	go func() {
		_, _ = registry.Gather()
		close(gatherDone)
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not start")
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown() did not cancel the probe")
	}
	<-gatherDone
}

func TestRuntimeConfigValidate(t *testing.T) {
	cfg := bbconfig.NewConfigWithDefaults()
	cfg.Modules = bbconfig.ModulesConfig{Modules: map[string]bbconfig.Module{
		"http_2xx": {Prober: "http", HTTP: bbconfig.DefaultHTTPProbe},
	}}
	cfg.Targets = []bbconfig.Target{{Name: "example", Address: "https://example.com", Module: "http_2xx"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !cfg.Validated() {
		t.Fatal("Validated() = false")
	}

	cfg.ConfigFile = "blackbox.yml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted both modules and config_file")
	}
}

func testRuntimeConfig(address string) bbconfig.Config {
	cfg := bbconfig.NewConfigWithDefaults()
	cfg.Modules = bbconfig.ModulesConfig{Modules: map[string]bbconfig.Module{
		"http_2xx": {Prober: "http", HTTP: bbconfig.DefaultHTTPProbe},
	}}
	cfg.Targets = []bbconfig.Target{{
		Name:    "example",
		Address: address,
		Module:  "http_2xx",
		Labels:  map[string]string{"environment": "test"},
	}}
	return cfg
}

func discardRuntimeLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func findRuntimeMetric(t *testing.T, families []*dto.MetricFamily, name string) *dto.Metric {
	t.Helper()
	for _, family := range families {
		if family.GetName() == name && len(family.Metric) > 0 {
			return family.Metric[0]
		}
	}
	t.Fatalf("metric %q not found", name)
	return nil
}

func runtimeLabelValue(metric *dto.Metric, name string) string {
	for _, pair := range metric.Label {
		if pair.GetName() == name {
			return pair.GetValue()
		}
	}
	return ""
}
