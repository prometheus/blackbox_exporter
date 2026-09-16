// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package prober

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	bbconfig "github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

// Runtime owns the collectors and cancellation context for one embedding.
type Runtime struct {
	lifecycle    *runtimeLifecycle
	collectors   []prometheus.Collector
	shutdownOnce sync.Once
	shutdownDone chan struct{}
}

type runtimeLifecycle struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	stopped bool
	active  sync.WaitGroup
}

// NewRuntime constructs collectors for all configured targets.
func NewRuntime(cfg bbconfig.RuntimeConfig, logger *slog.Logger) (*Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	lifecycle := &runtimeLifecycle{
		ctx:    ctx,
		cancel: cancel,
	}
	runtime := &Runtime{
		lifecycle:    lifecycle,
		shutdownDone: make(chan struct{}),
	}
	for _, target := range cfg.Targets {
		module, ok := cfg.Module(target.Module)
		if !ok {
			cancel()
			return nil, fmt.Errorf("config is missing module %q", target.Module)
		}
		runtime.collectors = append(runtime.collectors, &probeCollector{
			lifecycle:     lifecycle,
			target:        target,
			module:        module,
			maxTimeout:    cfg.MaxTimeout,
			timeoutOffset: cfg.ProbeTimeoutOffset,
			logger:        logger.With("module", target.Module, "target", target.Address),
		})
	}
	return runtime, nil
}

// Collectors returns the collectors belonging to this runtime.
func (r *Runtime) Collectors() []prometheus.Collector {
	return append([]prometheus.Collector(nil), r.collectors...)
}

// Shutdown cancels in-flight probes and waits for them to finish.
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.shutdownOnce.Do(func() {
		r.lifecycle.mu.Lock()
		r.lifecycle.stopped = true
		r.lifecycle.cancel()
		r.lifecycle.mu.Unlock()

		go func() {
			r.lifecycle.active.Wait()
			close(r.shutdownDone)
		}()
	})

	select {
	case <-r.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *runtimeLifecycle) beginProbe() (context.Context, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		return nil, false
	}
	l.active.Add(1)
	return l.ctx, true
}

func (l *runtimeLifecycle) endProbe() {
	l.active.Done()
}

type probeCollector struct {
	lifecycle     *runtimeLifecycle
	target        bbconfig.Target
	module        bbconfig.Module
	maxTimeout    time.Duration
	timeoutOffset time.Duration
	logger        *slog.Logger
	mu            sync.Mutex
}

func (*probeCollector) Describe(chan<- *prometheus.Desc) {
	// Probe metric sets are dynamic, so this is intentionally unchecked.
}

func (c *probeCollector) Collect(ch chan<- prometheus.Metric) {
	parentCtx, ok := c.lifecycle.beginProbe()
	if !ok {
		return
	}
	defer c.lifecycle.endProbe()

	c.mu.Lock()
	defer c.mu.Unlock()

	timeout := EffectiveTimeout(c.module.Timeout, c.maxTimeout, c.timeoutOffset)
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	registry := prometheus.NewRegistry()
	successGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})
	durationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})
	timeoutGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_timeout_seconds",
		Help: "Returns how long the probe timeout is in seconds",
	})
	registry.MustRegister(successGauge, durationGauge, timeoutGauge)

	probe, ok := Probers[c.module.Prober]
	if !ok {
		err := fmt.Errorf("unknown prober %q", c.module.Prober)
		ch <- prometheus.NewInvalidMetric(prometheus.NewInvalidDesc(err), err)
		return
	}
	start := time.Now()
	success := probe(ctx, c.target.Address, c.module, registry, c.logger)
	durationGauge.Set(time.Since(start).Seconds())
	timeoutGauge.Set(timeout.Seconds())
	if success {
		successGauge.Set(1)
	}

	labels := prometheus.Labels{
		"target":      c.target.Address,
		"module":      c.target.Module,
		"target_name": c.target.Name,
	}
	prometheus.WrapCollectorWith(labels, registry).Collect(ch)
}
