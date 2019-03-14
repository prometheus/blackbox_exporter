package prober

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

func TestCommonStatusStatusCodes(t *testing.T) {
	tests := []struct {
		StatusCode       int
		ValidStatusCodes []int
		ShouldSucceed    bool
	}{
		{200, []int{}, true},
		{201, []int{}, true},
		{299, []int{}, true},
		{300, []int{}, false},
		{404, []int{}, false},
	}
	for i, test := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.StatusCode)
		}))
		defer ts.Close()
		registry := prometheus.NewRegistry()
		recorder := httptest.NewRecorder()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result := ProbeCommonStatus(testCTX, ts.URL,
			config.Module{Timeout: time.Second, HTTP: config.HTTPProbe{IPProtocolFallback: true, ValidStatusCodes: test.ValidStatusCodes}}, registry, log.NewNopLogger())
		body := recorder.Body.String()
		if result != test.ShouldSucceed {
			t.Fatalf("Test %d had unexpected result: %s", i, body)
		}
	}
}

func TestConvertMetricsConversionOfValidMetrics(t *testing.T) {
	assert := assert.New(t)

	f, _ := os.Open("testdata/valid-metrics.txt")
	reader := bufio.NewReader(f)
	registry := prometheus.NewRegistry()

	success := convertMetrics(reader, registry, log.NewNopLogger())
	assert.True(success, "Failed to process valid metrics")

	results, _ := registry.Gather()
	assert.Len(results, 29, "Wrong number of metrics in the registry")

	for _, result := range results {
		if result.GetName() == "probe_commonstatus_failed_metrics" {
			assert.Zero((*result.GetMetric()[0]).GetCounter().GetValue())
		}
	}
}

func TestConvertLoadAvg_ok(t *testing.T) {
	assert := assert.New(t)

	// GIVEN
	input := []byte("LoadAvg: 1.94 3.44 5.07")

	la1Desc := prometheus.NewDesc("load_avertage1", "1m load average.", nil, nil)
	la1Metric := prometheus.MustNewConstMetric(la1Desc, prometheus.GaugeValue, float64(1.94))

	la5Desc := prometheus.NewDesc("load_avertage5", "5m load average.", nil, nil)
	la5Metric := prometheus.MustNewConstMetric(la5Desc, prometheus.GaugeValue, float64(3.44))

	la15Desc := prometheus.NewDesc("load_avertage15", "15m load average.", nil, nil)
	la15Metric := prometheus.MustNewConstMetric(la15Desc, prometheus.GaugeValue, float64(5.07))

	wants := []prometheus.Metric{la1Metric, la5Metric, la15Metric}
	registry := prometheus.NewRegistry()

	// WHEN
	err := convertLoadAvg(input, registry)

	// THEN
	assert.NoError(err)

	results, _ := registry.Gather()

	for _, want := range wants {
		var found bool
		// wantDesc := want.Desc()
		wantMetric := dto.Metric{}
		want.Write(&wantMetric)
		wantMetricStr := wantMetric.String()

		for _, result := range results {
			resultMetrics := result.GetMetric()
			for _, resultMetric := range resultMetrics {
				resultMetricStr := (*resultMetric).String()
				if resultMetricStr == wantMetricStr {
					found = true
					break
				}
			}
		}
		assert.True(found, "Failed to find %v", wantMetricStr)
	}
}

func TestConvertLoadAvg_invalidInput(t *testing.T) {
	assert := assert.New(t)

	// GIVEN
	invalidInput := []byte("LoadAvg: 1.94 3.44 5,07")
	registry := prometheus.NewRegistry()

	// WHEN
	err := convertLoadAvg(invalidInput, registry)

	// THEN
	assert.NotNilf(err, "convertLoadAvg should return error for invalid input")
}

func TestConvertNumberSeparators_ok(t *testing.T) {
	assert := assert.New(t)
	type testpair struct {
		metric []byte
		result float64
	}

	var tests = []testpair{
		{[]byte("MemoryUsed: 9,220,838,392"), 9220838392},
		{[]byte("MemoryUsed: 9.220.838.392"), 9220838392},
		{[]byte("MemoryUsed: 9220838392,01"), 9220838392.01},
		{[]byte("MemoryUsed: 9,220,838,392.01"), 9220838392.01},
		{[]byte("MemoryUsed: 9.220.838.392,01"), 9220838392.01},
		{[]byte("MemoryUsed: 4.997,14"), 4997.14},
		{[]byte("MemoryUsed: 4,997.14"), 4997.14},
		{[]byte("MemoryUsed: 0"), 0},
	}

	for _, test := range tests {
		registry := prometheus.NewRegistry()

		err := convertNumberSeparators(test.metric, registry)
		assert.NoError(err)

		wantDesc := prometheus.NewDesc("MemoryUsed", "", nil, nil)
		want := prometheus.MustNewConstMetric(wantDesc, prometheus.GaugeValue, test.result)
		wantMetric := dto.Metric{}
		want.Write(&wantMetric)
		wantMetricStr := wantMetric.String()

		results, _ := registry.Gather()
		resultMetricStr := (*results[0].GetMetric()[0]).String()

		assert.Equal(wantMetricStr, resultMetricStr, "metrics are different! Wanted: %v, got: %v, metric: %s", wantMetricStr, resultMetricStr, test.metric)
	}
}

func TestConvertStartupTime_ok(t *testing.T) {
	assert := assert.New(t)
	type testpair struct {
		metric    []byte
		timestamp int64
	}

	var tests = []testpair{
		{[]byte("StartupTime: Mon Jan 28 14:24:03 CET 2019"), 1548681843},
		{[]byte("StartupTime: Tue Jan 01 14:24:00 CET 2019"), 1546349040},
		{[]byte("StartupTime: Tue Jan 01 14:24:00 GMT 2019"), 1546352640},
	}

	for _, test := range tests {
		registry := prometheus.NewRegistry()

		err := convertStartupTime(test.metric, registry)
		assert.NoError(err)

		uptime := time.Since(time.Unix(test.timestamp, 0)).Seconds()

		results, _ := registry.Gather()
		resultValue := (*results[0].GetMetric()[0]).Counter.GetValue()
		assert.InDelta(uptime, resultValue, 1, "metrics are different! Wanted: %v, got: %v, metric: %s", uptime, resultValue, test.metric)
	}
}

func TestParseReleaseTag_ok(t *testing.T) {
	assert := assert.New(t)
	type testpair struct {
		metric []byte
		want   prometheus.Labels
	}

	var tests = []testpair{
		{[]byte("ReleaseTag: catalog.deployment.server-release-2019-01-21-A"), prometheus.Labels{"release_tag": "catalog.deployment.server-release-2019-01-21-A"}},
		{[]byte("ReleaseTag: DEV-ITD_123-bla-test"), prometheus.Labels{"release_tag": "DEV-ITD_123-bla-test"}},
		{[]byte("ReleaseTag: 0.0.32"), prometheus.Labels{"release_tag": "0.0.32"}},
	}

	for _, test := range tests {
		infoLabels := make(prometheus.Labels)

		err := parseReleaseTag(test.metric, &infoLabels)
		assert.NoError(err)
		if err != nil {
			return
		}

		assert.Equal(test.want, infoLabels, "the infoLabel is wrong! Wanted: %v, got: %v, metric: %s", test.want, infoLabels, test.metric)
	}
}

func TestCreateInfoMetric_ok(t *testing.T) {
	assert := assert.New(t)

	tests := []prometheus.Labels{
		prometheus.Labels{"release_tag": "DEV-ITD_123-bla-test", "branch": "HEAD", "build": ""},
		prometheus.Labels{"release_tag": "0.0.32"},
	}

	for _, labels := range tests {
		registry := prometheus.NewRegistry()

		createInfoMetric(&labels, registry)

		results, _ := registry.Gather()
		resultLabels := (*results[0].GetMetric()[0]).GetLabel()
		resultValue := (*results[0].GetMetric()[0]).Gauge.GetValue()

		assert.NotEmpty(resultLabels)

		for _, resultLabel := range resultLabels {
			assert.NotNil(labels[resultLabel.GetName()])
			assert.Equal(labels[resultLabel.GetName()], resultLabel.GetValue())
		}
		assert.Equal(float64(1), resultValue)
	}
}
