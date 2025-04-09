# Blackbox exporter

[![CI](https://github.com/prometheus/blackbox_exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/prometheus/blackbox_exporter/actions/workflows/ci.yml)
[![Docker Repository on Quay](https://quay.io/repository/prometheus/blackbox-exporter/status)][quay]
[![Docker Pulls](https://img.shields.io/docker/pulls/prom/blackbox-exporter.svg?maxAge=604800)][hub]

The blackbox exporter allows blackbox probing of endpoints over
HTTP, HTTPS, DNS, TCP, ICMP and gRPC.

## Running this software

### From binaries

Download the most suitable binary from [the releases tab](https://github.com/prometheus/blackbox_exporter/releases)

Then:

    ./blackbox_exporter <flags>


### Using the docker image

*Note: You may want to [enable ipv6 in your docker configuration](https://docs.docker.com/v17.09/engine/userguide/networking/default_network/ipv6/)*

    docker run --rm \
      -p 9115/tcp \
      --name blackbox_exporter \
      -v $(pwd):/config \
      quay.io/prometheus/blackbox-exporter:latest --config.file=/config/blackbox.yml

### Checking the results

Visiting [http://localhost:9115/probe?target=google.com&module=http_2xx](http://localhost:9115/probe?target=google.com&module=http_2xx)
will return metrics for a HTTP probe against google.com. The `probe_success`
metric indicates if the probe succeeded. Adding a `debug=true` parameter
will return debug information for that probe.

Metrics concerning the operation of the exporter itself are available at the
endpoint <http://localhost:9115/metrics>.

### TLS and basic authentication

The Blackbox Exporter supports TLS and basic authentication. This enables better
control of the various HTTP endpoints.

To use TLS and/or basic authentication, you need to pass a configuration file
using the `--web.config.file` parameter. The format of the file is described
[in the exporter-toolkit repository](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).

Note that the TLS and basic authentication settings affect all HTTP endpoints:
/metrics for scraping, /probe for probing, and the web UI.

## Building the software

### Local Build

    make


### Building with Docker

After a successful local build:

    docker build -t blackbox_exporter .

## [Configuration](CONFIGURATION.md)

Blackbox exporter is configured via a [configuration file](CONFIGURATION.md) and command-line flags (such as what configuration file to load, what port to listen on, and the logging format and level).

Blackbox exporter can reload its configuration file at runtime. If the new configuration is not well-formed, the changes will not be applied.
A configuration reload is triggered by sending a `SIGHUP` to the Blackbox exporter process or by sending a HTTP POST request to the `/-/reload` endpoint.

To view all available command-line flags, run `./blackbox_exporter -h`.

To specify which [configuration file](CONFIGURATION.md) to load, use the `--config.file` flag.

Additionally, an [example configuration](example.yml) is also available.

HTTP, HTTPS (via the `http` prober), DNS, TCP socket, ICMP and gRPC (see permissions section) are currently supported.
Additional modules can be defined to meet your needs.

The timeout of each probe is automatically determined from the `scrape_timeout` in the [Prometheus config](https://prometheus.io/docs/operating/configuration/#configuration-file), slightly reduced to allow for network delays. 
This can be further limited by the `timeout` in the Blackbox exporter config file. If neither is specified, it defaults to 120 seconds.

## Prometheus Configuration

Blackbox exporter implements the multi-target exporter pattern, so we advice
to read the guide [Understanding and using the multi-target exporter pattern
](https://prometheus.io/docs/guides/multi-target-exporter/) to get the general
idea about the configuration.

The blackbox exporter needs to be passed the target as a parameter, this can be
done with relabelling.

Example config:
```yml
scrape_configs:
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http_2xx]  # Look for a HTTP 200 response.
    static_configs:
      - targets:
        - http://prometheus.io    # Target to probe with http.
        - https://prometheus.io   # Target to probe with https.
        - http://example.com:8080 # Target to probe with http on port 8080.
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115  # The blackbox exporter's real hostname:port.
  - job_name: 'blackbox_exporter'  # collect blackbox exporter's operational metrics.
    static_configs:
      - targets: ['127.0.0.1:9115']
```

HTTP probes can accept an additional `hostname` parameter that will set `Host` header and TLS SNI. This can be especially useful with `dns_sd_config`:
```yaml
scrape_configs:
  - job_name: blackbox_all
    metrics_path: /probe
    params:
      module: [ http_2xx ]  # Look for a HTTP 200 response.
    dns_sd_configs:
      - names:
          - example.com
          - prometheus.io
        type: A
        port: 443
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
        replacement: https://$1/  # Make probe URL be like https://1.2.3.4:443/
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115  # The blackbox exporter's real hostname:port.
      - source_labels: [__meta_dns_name]
        target_label: __param_hostname  # Make domain name become 'Host' header for probe requests
      - source_labels: [__meta_dns_name]
        target_label: vhost  # and store it in 'vhost' label
```

## Permissions

The ICMP probe requires elevated privileges to function:

* *Windows*: Administrator privileges are required.
* *Linux*: either a user with a group within `net.ipv4.ping_group_range`, the
  `CAP_NET_RAW` capability or the root user is required.
  * Your distribution may configure `net.ipv4.ping_group_range` by default in
    `/etc/sysctl.conf` or similar. If not you can set
    `net.ipv4.ping_group_range = 0  2147483647` to allow any user the ability
    to use ping.
  * Alternatively the capability can be set by executing `setcap cap_net_raw+ep
    blackbox_exporter`
* *BSD*: root user is required.
* *OS X*: No additional privileges are needed.

[hub]: https://hub.docker.com/r/prom/blackbox-exporter/
[quay]: https://quay.io/repository/prometheus/blackbox-exporter
