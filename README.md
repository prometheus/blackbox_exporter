# Blackbox exporter [![Build Status](https://travis-ci.org/prometheus/blackbox_exporter.svg)][travis]

[![CircleCI](https://circleci.com/gh/prometheus/blackbox_exporter/tree/master.svg?style=shield)][circleci]
[![Docker Repository on Quay](https://quay.io/repository/prometheus/blackbox-exporter/status)][quay]
[![Docker Pulls](https://img.shields.io/docker/pulls/prom/blackbox-exporter.svg?maxAge=604800)][hub]

The blackbox exporter allows blackbox probing of endpoints over
HTTP, HTTPS, DNS, TCP and ICMP.

## Building and running

### Local Build

    make
    ./blackbox_exporter <flags>

Visiting [http://localhost:9115/probe?target=google.com&module=http_2xx](http://localhost:9115/probe?target=google.com&module=http_2xx)
will return metrics for a HTTP probe against google.com. The `probe_success` metric indicates if the probe succeeded.

### Building with Docker

    docker build -t blackbox_exporter .
    docker run -d -p 9115:9115 --name blackbox_exporter -v `pwd`:/config blackbox_exporter -config.file=/config/blackbox.yml

## Configuration

A configuration showing all options is below:
```yml
modules:
  http_2xx_example:
    prober: http
    timeout: 5s
    http:
      valid_status_codes: []  # Defaults to 2xx
      method: GET
      headers:
        Host: vhost.example.com
        Accept-Language: en-US
      no_follow_redirects: false
      fail_if_ssl: false
      fail_if_not_ssl: false
      fail_if_matches_regexp:
        - "Could not connect to database"
      fail_if_not_matches_regexp:
        - "Download the latest version here"
      tls_config:
        insecure_skip_verify: false
      protocol: "tcp" # accepts "tcp/tcp4/tcp6", defaults to "tcp"
      preferred_ip_protocol: "ip4" # used for "tcp", defaults to "ip6"
  http_post_2xx:
    prober: http
    timeout: 5s
    http:
      method: POST
      headers:
        Content-Type: application/json
      body: '{}'
  tcp_connect_v4_example:
    prober: tcp
    timeout: 5s
    tcp:
      protocol: "tcp4"
  irc_banner_example:
    prober: tcp
    timeout: 5s
    tcp:
      query_response:
        - send: "NICK prober"
        - send: "USER prober prober prober :prober"
        - expect: "PING :([^ ]+)"
          send: "PONG ${1}"
        - expect: "^:[^ ]+ 001"
  icmp_example:
    prober: icmp
    timeout: 5s
    icmp:
      protocol: "icmp"
      preferred_ip_protocol: "ip4"
  dns_udp_example:
    prober: dns
    timeout: 5s
    dns:
      query_name: "www.prometheus.io"
      query_type: "A"
      valid_rcodes:
      - NOERROR
      validate_answer_rrs:
        fail_if_matches_regexp:
        - ".*127.0.0.1"
        fail_if_not_matches_regexp:
        - "www.prometheus.io.\t300\tIN\tA\t127.0.0.1"
      validate_authority_rrs:
        fail_if_matches_regexp:
        - ".*127.0.0.1"
      validate_additional_rrs:
        fail_if_matches_regexp:
        - ".*127.0.0.1"
  dns_tcp_example:
    prober: dns
    dns:
      protocol: "tcp" # accepts "tcp/tcp4/tcp6/udp/udp4/udp6", defaults to "udp"
      preferred_ip_protocol: "ip4" # used for "udp/tcp", defaults to "ip6"
      query_name: "www.prometheus.io"
```

HTTP, HTTPS (via the `http` prober), DNS, TCP socket and ICMP (v4 only, see permissions section) are currently supported.
Additional modules can be defined to meet your needs.


## Prometheus Configuration

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
        replacement: 127.0.0.1:9115  # Blackbox exporter.
```

## Permissions

The ICMP probe requires elevated privileges to function:

* *Windows*: Administrator privileges are required.
* *Linux*: root user _or_ `CAP_NET_RAW` capability is required.
  * Can be set by executing `setcap cap_net_raw+ep blackbox_exporter`
* *BSD / OS X*: root user is required.

[circleci]: https://circleci.com/gh/prometheus/blackbox_exporter
[hub]: https://hub.docker.com/r/prom/blackbox-exporter/
[travis]: https://travis-ci.org/prometheus/blackbox_exporter
[quay]: https://quay.io/repository/prometheus/blackbox-exporter
