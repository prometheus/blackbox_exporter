// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package prober

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	bbconfig "github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Runtime owns the collectors and cancellation context for one embedding.
type Runtime struct {
	cancel     context.CancelFunc
	collectors []prometheus.Collector
	stopOnce   sync.Once
}

// NewRuntime constructs collectors for all configured targets.
func NewRuntime(cfg bbconfig.Config, logger *slog.Logger) (*Runtime, error) {
	if !cfg.Validated() {
		return nil, errors.New("config has not been validated; call cfg.Validate before NewRuntime")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &Runtime{cancel: cancel}
	for _, target := range cfg.Targets {
		module, ok := cfg.Module(target.Module)
		if !ok {
			cancel()
			return nil, fmt.Errorf("validated config is missing module %q", target.Module)
		}
		runtime.collectors = append(runtime.collectors, &probeCollector{
			ctx:           ctx,
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

// Shutdown cancels in-flight probes.
func (r *Runtime) Shutdown(context.Context) error {
	r.stopOnce.Do(r.cancel)
	return nil
}

type probeCollector struct {
	ctx           context.Context
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
	c.mu.Lock()
	defer c.mu.Unlock()

	timeout := EffectiveTimeout(c.module.Timeout, c.maxTimeout, c.timeoutOffset)
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
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

	families, err := registry.Gather()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewInvalidDesc(err), err)
		return
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			forwarded, err := c.forwardMetric(family, metric)
			if err != nil {
				ch <- prometheus.NewInvalidMetric(prometheus.NewInvalidDesc(err), err)
				continue
			}
			ch <- forwarded
		}
	}
}

func (c *probeCollector) forwardMetric(family *dto.MetricFamily, metric *dto.Metric) (prometheus.Metric, error) {
	pairs := append([]*dto.LabelPair(nil), metric.Label...)
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].GetName() < pairs[j].GetName()
	})
	labelNames := make([]string, 0, len(pairs))
	labelValues := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		labelNames = append(labelNames, pair.GetName())
		labelValues = append(labelValues, pair.GetValue())
	}
	constLabels := prometheus.Labels{
		"target":      c.target.Address,
		"module":      c.target.Module,
		"target_name": c.target.Name,
	}
	for name, value := range c.target.Labels {
		constLabels[name] = value
	}
	desc := prometheus.NewDesc(family.GetName(), family.GetHelp(), labelNames, constLabels)

	var (
		result prometheus.Metric
		err    error
	)
	switch family.GetType() {
	case dto.MetricType_COUNTER:
		result, err = prometheus.NewConstMetric(desc, prometheus.CounterValue, metric.GetCounter().GetValue(), labelValues...)
	case dto.MetricType_GAUGE:
		result, err = prometheus.NewConstMetric(desc, prometheus.GaugeValue, metric.GetGauge().GetValue(), labelValues...)
	case dto.MetricType_UNTYPED:
		result, err = prometheus.NewConstMetric(desc, prometheus.UntypedValue, metric.GetUntyped().GetValue(), labelValues...)
	case dto.MetricType_HISTOGRAM:
		buckets := make(map[float64]uint64, len(metric.GetHistogram().Bucket))
		for _, bucket := range metric.GetHistogram().Bucket {
			buckets[bucket.GetUpperBound()] = bucket.GetCumulativeCount()
		}
		result, err = prometheus.NewConstHistogram(
			desc,
			metric.GetHistogram().GetSampleCount(),
			metric.GetHistogram().GetSampleSum(),
			buckets,
			labelValues...,
		)
	case dto.MetricType_SUMMARY:
		quantiles := make(map[float64]float64, len(metric.GetSummary().Quantile))
		for _, quantile := range metric.GetSummary().Quantile {
			quantiles[quantile.GetQuantile()] = quantile.GetValue()
		}
		result, err = prometheus.NewConstSummary(
			desc,
			metric.GetSummary().GetSampleCount(),
			metric.GetSummary().GetSampleSum(),
			quantiles,
			labelValues...,
		)
	default:
		return nil, fmt.Errorf("metric %q has unsupported type %s", family.GetName(), family.GetType())
	}
	if err != nil {
		return nil, err
	}
	if metric.TimestampMs != nil {
		result = prometheus.NewMetricWithTimestamp(time.UnixMilli(metric.GetTimestampMs()), result)
	}
	return result, nil
}
