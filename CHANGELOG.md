## master / unreleased

BREAKING CHANGES:

Changes:

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]

## 0.26.0 / 2025-02-26

* [CHANGE] adopt log/slog, drop go-kit/log #1311
* [FEATURE] Add metric to record tls ciphersuite negotiated during handshake #1203
* [FEATURE] Add a way to export labels with content matched by the probe #1284
* [FEATURE] Reports Certificate Serial number #1333
* [ENHANCEMENT] Enable misspell linter #1248
* [ENHANCEMENT] Fix incorrect parameters name in documentation #1126
* [ENHANCEMENT] Add stale workflow to start sync with stale.yaml in prometheus #1170
* [ENHANCEMENT] Update CONFIGURATION.md to clarify that valid_status_codes expects a list #1335
* [ENHANCEMENT] Skip failing IPv6 tests in test CI Pipeline #1342
* [ENHANCEMENT] Add RabbitMQ probe example #1349
* [BUGFIX] Only register grpc TLS metrics on successful handshake #1338

## 0.25.0 / 2024-04-09

* [FEATURE] Allow to get Probe logs by target #1063
* [FEATURE] Log errors from probe #1091
* [BUGFIX] Prevent logging confusing error message #1059
* [BUGFIX] Explicit registration of internal exporter metrics 1060

## 0.24.0 / 2023-05-16

* [CHANGE] Make Proxy Connect Headers consistent with Prometheus #1008
* [FEATURE] Add hostname parameter for TCP probe #981
* [FEATURE] Add support for HTTP request body as file #987

## 0.23.0 / 2022-12-02

* [SECURITY] Update Exporter Toolkit (CVE-2022-46146) #979
* [FEATURE] Support multiple Listen Addresses and systemd socket activation #979
* [FEATURE] Add leaf certificate details in a new `probe_ssl_last_chain_info` metric. #943
* [FEATURE] DNS: Add `Add probe_dns_query_succeeded` metric. #990

## 0.22.0 / 2022-08-02

* [FEATURE] HTTP: Add `skip_resolve_phase_with_proxy` option. #944
* [ENHANCEMENT] OAuth: Use Blackbox Exporter user agent when doing OAuth2
  authenticated requests. #948
* [ENHANCEMENT] Print usage and help to stdout instead of stderr. #928


## 0.21.1 / 2022-06-17

* [BUGFIX] Fix a data race in HTTP probes. #929

## 0.21.0 / 2022-05-30

This Prometheus release is built with go1.18, which contains two noticeable
changes related to TLS and HTTP:

1. [TLS 1.0 and 1.1 disabled by default client-side](https://go.dev/doc/go1.18#tls10).
   Blackbox Exporter users can override this with the `min_version` parameter of
   [tls_config](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#tls_config).
2. [Certificates signed with the SHA-1 hash function are rejected](https://go.dev/doc/go1.18#sha1).
   This doesn't apply to self-signed root certificates.

* [BUGFIX] Prevent setting negative timeouts when using a small scrape interval. #869

## 0.20.0 / 2022-03-16

* [FEATURE] Add support for grpc health check. #835
* [FEATURE] Add hostname parameter. #823
* [ENHANCEMENT] Add body_size_limit option to http module. #836
* [ENHANCEMENT] Change default user agent. #557
* [ENHANCEMENT] Add control of recursion desired flag for DNS probes. #859
* [ENHANCEMENT] Delay init of http phase values. #865
* [BUGFIX] Fix IP hash. #863

## 0.19.0 / 2021-05-10

In the HTTP probe, `no_follow_redirects` has been changed to `follow_redirects`.
This release accepts both, with a precedence to the `no_follow_redirects` parameter.
In the next release, `no_follow_redirects` will be removed.

* [CHANGE] HTTP probe: `no_follow_redirects` has been renamed to `follow_redirects`. #784
* [FEATURE] Add support for decompression of HTTP responses. #764
* [FEATURE] Enable TLS and basic authentication. #730
* [FEATURE] HTTP probe: *experimental* OAuth2 support. #784
* [ENHANCEMENT] Add a health endpoint. #752
* [ENHANCEMENT] Add a metric for unknown probes. #716
* [ENHANCEMENT] Use preferred protocol first when resolving hostname. #728
* [ENHANCEMENT] Validating the configuration tries to compile regexes. #729
* [BUGFIX] HTTP probe: Fix error checking. #723
* [BUGFIX] HTTP probe: Fix how the TLS phase is calculated. #758
