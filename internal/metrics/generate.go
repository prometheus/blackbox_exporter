package metrics

//go:generate weaver registry generate --registry=../../semconv --templates=/home/tbraack/work/promconv/templates --param module=github.com/prometheus/blackbox_exporter/internal/metrics go .
//go:generate gofmt -s -w .
