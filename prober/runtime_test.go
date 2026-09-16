// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package prober

import (
	"context"
	"errors"
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
	}
	for name, want := range wantLabels {
		if got := runtimeLabelValue(success, name); got != want {
			t.Errorf("label %q = %q; want %q", name, got, want)
		}
	}
	if got := len(success.Label); got != len(wantLabels) {
		t.Errorf("probe_success labels = %d; want %d", got, len(wantLabels))
	}
}

func TestRuntimeProbeTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
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

func TestRuntimeShutdownWaitsForProbe(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	release := make(chan struct{})
	originalProber := Probers["http"]
	Probers["http"] = func(ctx context.Context, _ string, _ bbconfig.Module, _ *prometheus.Registry, _ *slog.Logger) bool {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		return false
	}
	t.Cleanup(func() {
		Probers["http"] = originalProber
	})

	cfg := testRuntimeConfig("https://example.com")
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

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- runtime.Shutdown(context.Background())
	}()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown() did not cancel the probe")
	}
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown() returned before the probe completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown() did not return after the probe completed")
	}
	select {
	case <-gatherDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Gather() did not return after the probe completed")
	}
}

func TestRuntimeShutdownHonorsContext(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	originalProber := Probers["http"]
	Probers["http"] = func(ctx context.Context, _ string, _ bbconfig.Module, _ *prometheus.Registry, _ *slog.Logger) bool {
		close(started)
		<-ctx.Done()
		<-release
		return false
	}
	t.Cleanup(func() {
		Probers["http"] = originalProber
	})

	runtime, err := NewRuntime(testRuntimeConfig("https://example.com"), discardRuntimeLogger())
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

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := runtime.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v; want %v", err, context.DeadlineExceeded)
	}

	close(release)
	select {
	case <-gatherDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Gather() did not return after the probe completed")
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}
}

func TestRuntimeDoesNotStartProbesAfterShutdown(t *testing.T) {
	probed := make(chan struct{}, 1)
	originalProber := Probers["http"]
	Probers["http"] = func(context.Context, string, bbconfig.Module, *prometheus.Registry, *slog.Logger) bool {
		probed <- struct{}{}
		return true
	}
	t.Cleanup(func() {
		Probers["http"] = originalProber
	})

	runtime, err := NewRuntime(testRuntimeConfig("https://example.com"), discardRuntimeLogger())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(runtime.Collectors()...)
	if _, err := registry.Gather(); err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	select {
	case <-probed:
		t.Fatal("Gather() started a probe after Shutdown()")
	default:
	}
}

func TestRuntimeValidatesConfig(t *testing.T) {
	cfg := bbconfig.NewRuntimeConfigWithDefaults()
	cfg.Modules = bbconfig.Config{Modules: map[string]bbconfig.Module{
		"http_2xx": {Prober: "http", HTTP: bbconfig.DefaultHTTPProbe},
	}}
	cfg.Targets = []bbconfig.Target{{Name: "example", Address: "https://example.com", Module: "http_2xx"}}
	runtime, err := NewRuntime(cfg, discardRuntimeLogger())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Shutdown(context.Background())

	cfg.ConfigFile = "blackbox.yml"
	if _, err := NewRuntime(cfg, discardRuntimeLogger()); err == nil {
		t.Fatal("NewRuntime() accepted both modules and config_file")
	}
}

func TestRuntimeRevalidatesConfig(t *testing.T) {
	cfg := testRuntimeConfig("https://example.com")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	cfg.MaxTimeout = 0
	if _, err := NewRuntime(cfg, discardRuntimeLogger()); err == nil {
		t.Fatal("NewRuntime() accepted config made invalid after Validate()")
	}
}

func testRuntimeConfig(address string) bbconfig.RuntimeConfig {
	cfg := bbconfig.NewRuntimeConfigWithDefaults()
	cfg.Modules = bbconfig.Config{Modules: map[string]bbconfig.Module{
		"http_2xx": {Prober: "http", HTTP: bbconfig.DefaultHTTPProbe},
	}}
	cfg.Targets = []bbconfig.Target{{
		Name:    "example",
		Address: address,
		Module:  "http_2xx",
	}}
	return cfg
}

func discardRuntimeLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
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
