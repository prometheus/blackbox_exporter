# Blackbox exporter

The blackbox exporter allows blackbox probing of endpoints over
HTTP, HTTPS and TCP.

## Building and running

    make
    ./blackbox_exporter <flags>

## Prometheus Configuration

The blackbox exporter needs to be passed the target as a parameter, this can be
done with relabelling.

Example config:
```
scrape_config:
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http2xx]  # Look for a HTTP 200 response.
    target_groups:
      - targets:
        - http://mywebsite.com  # Target to probe
    relabel_configs:
      - source_labels: [__address__]
        regex: (.*):80
        target_label: __param_target
        replacement: ${1}
      - source_labels: [__param_address]
        regex: (.*)
        target_label: instance
        replacement: ${1}
      - source_labels: []
        regex: .*
        target_label: __address__
        replacement: 127.0.0.1:9115  # Blackbox exporter.
```
