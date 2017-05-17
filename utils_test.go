package main

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// Check if expected results are in the registry
func checkRegistryResults(expRes map[string]float64, mfs []*dto.MetricFamily, t *testing.T) {
	res := make(map[string]float64)
	for i := range mfs {
		res[mfs[i].GetName()] = mfs[i].Metric[0].GetGauge().GetValue()
	}
	for k, v := range expRes {
		if val, ok := res[k]; !ok || val != v {
			t.Fatalf("Expected: %v: %v, got: %v: %v", k, v, k, val)
		}
	}
}
