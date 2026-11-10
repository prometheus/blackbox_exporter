# Metrics

The blackbox exporter serves metrics on two endpoints:

- `/metrics` returns metrics about the exporter itself.
- `/probe` runs a probe and returns metrics about it. Which metrics a probe
  returns depends on the prober of the module, the module configuration and
  what happened during the probe.

The tables below are generated from the metric definitions in the source code
by `make metrics-docs`. Do not edit the text between the
`BEGIN GENERATED METRICS` and `END GENERATED METRICS` markers by hand: a test
fails when it is out of date.

A ✓ in the prober table means that the prober can return the metric, not that
every probe does. [When metrics appear](#when-metrics-appear) lists the
conditions.

<!-- BEGIN GENERATED METRICS: run "make metrics-docs" -->

## Exporter metrics

Served on `/metrics`.

| Metric | Type | Labels | Help |
|---|---|---|---|
| `blackbox_exporter_build_info` | gauge | `version`, `revision`, `branch`, `goversion`, `goos`, `goarch`, `tags` | A metric with a constant '1' value labeled by version, revision, branch, goversion from which blackbox_exporter was built, and the goos and goarch for the build. |
| `blackbox_exporter_config_last_reload_success_timestamp_seconds` | gauge |  | Timestamp of the last successful configuration reload. |
| `blackbox_exporter_config_last_reload_successful` | gauge |  | Blackbox exporter config loaded successfully. |
| `blackbox_module_unknown_total` | counter |  | Count of unknown modules requested by probes |

## Metrics returned by every probe

Returned by `/probe` for every module, whatever its prober.

| Metric | Type | Labels | Help |
|---|---|---|---|
| `probe_duration_seconds` | gauge |  | Returns how long the probe took to complete in seconds |
| `probe_success` | gauge |  | Displays whether or not the probe was a success |
| `probe_timeout_seconds` | gauge |  | Returns how long the probe timeout is in seconds |

## Metrics by prober

A ✓ means that the prober can return the metric.

| Metric | http | tcp | icmp | dns | grpc | unix | websocket |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `probe_dns_additional_rrs` | | | | ✓ | | | |
| `probe_dns_answer_rrs` | | | | ✓ | | | |
| `probe_dns_authority_rrs` | | | | ✓ | | | |
| `probe_dns_duration_seconds` | | | | ✓ | | | |
| `probe_dns_lookup_time_seconds` | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ |
| `probe_dns_query_succeeded` | | | | ✓ | | | |
| `probe_dns_serial` | | | | ✓ | | | |
| `probe_expect_info` | | ✓ | | | | ✓ | |
| `probe_failed_due_to_bytes` | | ✓ | | | | ✓ | |
| `probe_failed_due_to_cel` | ✓ | | | | | | |
| `probe_failed_due_to_regex` | ✓ | ✓ | | | | ✓ | |
| `probe_grpc_duration_seconds` | | | | | ✓ | | |
| `probe_grpc_healthcheck_response` | | | | | ✓ | | |
| `probe_grpc_ssl` | | | | | ✓ | | |
| `probe_grpc_status_code` | | | | | ✓ | | |
| `probe_http_content_length` | ✓ | | | | | | |
| `probe_http_duration_seconds` | ✓ | | | | | | |
| `probe_http_last_modified_timestamp_seconds` | ✓ | | | | | | |
| `probe_http_redirects` | ✓ | | | | | | |
| `probe_http_ssl` | ✓ | | | | | | |
| `probe_http_status_code` | ✓ | | | | | | |
| `probe_http_uncompressed_body_length` | ✓ | | | | | | |
| `probe_http_version` | ✓ | | | | | | |
| `probe_icmp_duration_seconds` | | | ✓ | | | | |
| `probe_icmp_reply_hop_limit` | | | ✓ | | | | |
| `probe_ip_addr_hash` | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ |
| `probe_ip_protocol` | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ |
| `probe_ssl_crl_available` | ✓ | ✓ | | | ✓ | ✓ | |
| `probe_ssl_crl_fetch_time_seconds` | ✓ | ✓ | | | ✓ | ✓ | |
| `probe_ssl_crl_next_update_timestamp_seconds` | ✓ | ✓ | | | ✓ | ✓ | |
| `probe_ssl_crl_revoked` | ✓ | ✓ | | | ✓ | ✓ | |
| `probe_ssl_crl_stale` | ✓ | ✓ | | | ✓ | ✓ | |
| `probe_ssl_earliest_cert_expiry` | ✓ | ✓ | | | ✓ | ✓ | |
| `probe_ssl_last_chain_expiry_timestamp_seconds` | ✓ | ✓ | | | | ✓ | |
| `probe_ssl_last_chain_info` | ✓ | ✓ | | | ✓ | ✓ | |
| `probe_tls_cipher_info` | ✓ | ✓ | | | | ✓ | |
| `probe_tls_version_info` | ✓ | ✓ | | | ✓ | ✓ | |
| `probe_websocket_connection_upgraded` | | | | | | | ✓ |
| `probe_websocket_duration_seconds` | | | | | | | ✓ |
| `probe_websocket_failed_due_to_regex` | | | | | | | ✓ |
| `probe_websocket_status_code` | | | | | | | ✓ |

### http

| Metric | Type | Labels | Help |
|---|---|---|---|
| `probe_dns_lookup_time_seconds` | gauge |  | Returns the time taken for probe dns lookup in seconds |
| `probe_failed_due_to_cel` | gauge |  | Indicates if probe failed due to CEL expression not matching |
| `probe_failed_due_to_regex` | gauge |  | Indicates if probe failed due to regex |
| `probe_http_content_length` | gauge |  | Length of http content response |
| `probe_http_duration_seconds` | gauge | `phase` | Duration of http request by phase, summed over all redirects |
| `probe_http_last_modified_timestamp_seconds` | gauge |  | Returns the Last-Modified HTTP response header in unixtime |
| `probe_http_redirects` | gauge |  | The number of redirects |
| `probe_http_ssl` | gauge |  | Indicates if SSL was used for the final redirect |
| `probe_http_status_code` | gauge |  | Response HTTP status code |
| `probe_http_uncompressed_body_length` | gauge |  | Length of uncompressed response body |
| `probe_http_version` | gauge |  | Returns the version of HTTP of the probe response |
| `probe_ip_addr_hash` | gauge |  | Specifies the hash of IP address. It's useful to detect if the IP address changes. |
| `probe_ip_protocol` | gauge |  | Specifies whether probe ip protocol is IP4 or IP6 |
| `probe_ssl_crl_available` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the cert has CRL distribution points and the CRL was fetchable (0/1) |
| `probe_ssl_crl_fetch_time_seconds` | gauge |  | Total time spent fetching CRLs in seconds |
| `probe_ssl_crl_next_update_timestamp_seconds` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | CRL nextUpdate as a Unix timestamp in seconds |
| `probe_ssl_crl_revoked` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the certificate appears on its CRL (0/1) |
| `probe_ssl_crl_stale` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the CRL is past its nextUpdate (0/1) |
| `probe_ssl_earliest_cert_expiry` | gauge |  | Returns last SSL chain expiry in unixtime |
| `probe_ssl_last_chain_expiry_timestamp_seconds` | gauge |  | Returns last SSL chain expiry in timestamp |
| `probe_ssl_last_chain_info` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber` | Contains SSL leaf certificate information |
| `probe_tls_cipher_info` | gauge | `cipher` | Returns the TLS cipher negotiated during handshake |
| `probe_tls_version_info` | gauge | `version` | Returns the TLS version used or NaN when unknown |

### tcp

| Metric | Type | Labels | Help |
|---|---|---|---|
| `probe_dns_lookup_time_seconds` | gauge |  | Returns the time taken for probe dns lookup in seconds |
| `probe_expect_info` | gauge | names set by `query_response[].labels` | Explicit content matched |
| `probe_failed_due_to_bytes` | gauge |  | Indicates if probe failed due to bytes |
| `probe_failed_due_to_regex` | gauge |  | Indicates if probe failed due to regex |
| `probe_ip_addr_hash` | gauge |  | Specifies the hash of IP address. It's useful to detect if the IP address changes. |
| `probe_ip_protocol` | gauge |  | Specifies whether probe ip protocol is IP4 or IP6 |
| `probe_ssl_crl_available` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the cert has CRL distribution points and the CRL was fetchable (0/1) |
| `probe_ssl_crl_fetch_time_seconds` | gauge |  | Total time spent fetching CRLs in seconds |
| `probe_ssl_crl_next_update_timestamp_seconds` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | CRL nextUpdate as a Unix timestamp in seconds |
| `probe_ssl_crl_revoked` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the certificate appears on its CRL (0/1) |
| `probe_ssl_crl_stale` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the CRL is past its nextUpdate (0/1) |
| `probe_ssl_earliest_cert_expiry` | gauge |  | Returns last SSL chain expiry in unixtime |
| `probe_ssl_last_chain_expiry_timestamp_seconds` | gauge |  | Returns last SSL chain expiry in timestamp |
| `probe_ssl_last_chain_info` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber` | Contains SSL leaf certificate information |
| `probe_tls_cipher_info` | gauge | `cipher` | Returns the TLS cipher negotiated during handshake |
| `probe_tls_version_info` | gauge | `version` | Returns the TLS version used or NaN when unknown |

### icmp

| Metric | Type | Labels | Help |
|---|---|---|---|
| `probe_dns_lookup_time_seconds` | gauge |  | Returns the time taken for probe dns lookup in seconds |
| `probe_icmp_duration_seconds` | gauge | `phase` | Duration of icmp request by phase |
| `probe_icmp_reply_hop_limit` | gauge |  | Replied packet hop limit (TTL for ipv4) |
| `probe_ip_addr_hash` | gauge |  | Specifies the hash of IP address. It's useful to detect if the IP address changes. |
| `probe_ip_protocol` | gauge |  | Specifies whether probe ip protocol is IP4 or IP6 |

### dns

| Metric | Type | Labels | Help |
|---|---|---|---|
| `probe_dns_additional_rrs` | gauge |  | Returns number of entries in the additional resource record list |
| `probe_dns_answer_rrs` | gauge |  | Returns number of entries in the answer resource record list |
| `probe_dns_authority_rrs` | gauge |  | Returns number of entries in the authority resource record list |
| `probe_dns_duration_seconds` | gauge | `phase` | Duration of DNS request by phase |
| `probe_dns_lookup_time_seconds` | gauge |  | Returns the time taken for probe dns lookup in seconds |
| `probe_dns_query_succeeded` | gauge |  | Displays whether or not the query was executed successfully |
| `probe_dns_serial` | gauge |  | Returns the serial number of the zone |
| `probe_ip_addr_hash` | gauge |  | Specifies the hash of IP address. It's useful to detect if the IP address changes. |
| `probe_ip_protocol` | gauge |  | Specifies whether probe ip protocol is IP4 or IP6 |

### grpc

| Metric | Type | Labels | Help |
|---|---|---|---|
| `probe_dns_lookup_time_seconds` | gauge |  | Returns the time taken for probe dns lookup in seconds |
| `probe_grpc_duration_seconds` | gauge | `phase` | Duration of gRPC request by phase |
| `probe_grpc_healthcheck_response` | gauge | `serving_status` | Response HealthCheck response |
| `probe_grpc_ssl` | gauge |  | Indicates if SSL was used for the connection |
| `probe_grpc_status_code` | gauge |  | Response gRPC status code |
| `probe_ip_addr_hash` | gauge |  | Specifies the hash of IP address. It's useful to detect if the IP address changes. |
| `probe_ip_protocol` | gauge |  | Specifies whether probe ip protocol is IP4 or IP6 |
| `probe_ssl_crl_available` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the cert has CRL distribution points and the CRL was fetchable (0/1) |
| `probe_ssl_crl_fetch_time_seconds` | gauge |  | Total time spent fetching CRLs in seconds |
| `probe_ssl_crl_next_update_timestamp_seconds` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | CRL nextUpdate as a Unix timestamp in seconds |
| `probe_ssl_crl_revoked` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the certificate appears on its CRL (0/1) |
| `probe_ssl_crl_stale` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the CRL is past its nextUpdate (0/1) |
| `probe_ssl_earliest_cert_expiry` | gauge |  | Returns last SSL chain expiry in unixtime |
| `probe_ssl_last_chain_info` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber` | Contains SSL leaf certificate information |
| `probe_tls_version_info` | gauge | `version` | Returns the TLS version used or NaN when unknown |

### unix

| Metric | Type | Labels | Help |
|---|---|---|---|
| `probe_expect_info` | gauge | names set by `query_response[].labels` | Explicit content matched |
| `probe_failed_due_to_bytes` | gauge |  | Indicates if probe failed due to bytes |
| `probe_failed_due_to_regex` | gauge |  | Indicates if probe failed due to regex |
| `probe_ssl_crl_available` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the cert has CRL distribution points and the CRL was fetchable (0/1) |
| `probe_ssl_crl_fetch_time_seconds` | gauge |  | Total time spent fetching CRLs in seconds |
| `probe_ssl_crl_next_update_timestamp_seconds` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | CRL nextUpdate as a Unix timestamp in seconds |
| `probe_ssl_crl_revoked` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the certificate appears on its CRL (0/1) |
| `probe_ssl_crl_stale` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber`, `chain_pos`, `crl_url` | Whether the CRL is past its nextUpdate (0/1) |
| `probe_ssl_earliest_cert_expiry` | gauge |  | Returns last SSL chain expiry in unixtime |
| `probe_ssl_last_chain_expiry_timestamp_seconds` | gauge |  | Returns last SSL chain expiry in timestamp |
| `probe_ssl_last_chain_info` | gauge | `fingerprint_sha256`, `subject`, `issuer`, `subjectalternative`, `serialnumber` | Contains SSL leaf certificate information |
| `probe_tls_cipher_info` | gauge | `cipher` | Returns the TLS cipher negotiated during handshake |
| `probe_tls_version_info` | gauge | `version` | Returns the TLS version used or NaN when unknown |

### websocket

| Metric | Type | Labels | Help |
|---|---|---|---|
| `probe_dns_lookup_time_seconds` | gauge |  | Returns the time taken for probe dns lookup in seconds |
| `probe_ip_addr_hash` | gauge |  | Specifies the hash of IP address. It's useful to detect if the IP address changes. |
| `probe_ip_protocol` | gauge |  | Specifies whether probe ip protocol is IP4 or IP6 |
| `probe_websocket_connection_upgraded` | gauge |  | Indicates if the websocket connection was successfully upgraded |
| `probe_websocket_duration_seconds` | gauge | `phase` | Duration of websocket request by phase |
| `probe_websocket_failed_due_to_regex` | gauge |  | Indicates if probe failed due to regex |
| `probe_websocket_status_code` | gauge |  | Response HTTP status code |

<!-- END GENERATED METRICS -->

## When metrics appear

### Exporter

Besides the metrics above, `/metrics` returns the standard Go runtime
(`go_*`) and process (`process_*`) metrics of the Prometheus Go client, and
`promhttp_metric_handler_*` metrics about the `/metrics` handler itself.

### TLS

The TLS metrics are `probe_ssl_earliest_cert_expiry`,
`probe_ssl_last_chain_expiry_timestamp_seconds`, `probe_ssl_last_chain_info`,
`probe_tls_version_info` and `probe_tls_cipher_info`.

- `http` returns them when the final response, after any redirects, came over
  TLS.
- `grpc` returns `probe_ssl_earliest_cert_expiry`, `probe_ssl_last_chain_info`
  and `probe_tls_version_info` when the connection uses TLS. It does not
  return `probe_ssl_last_chain_expiry_timestamp_seconds` or
  `probe_tls_cipher_info`.
- `tcp` and `unix` return them when the module sets `tls: true`, or after a
  `query_response` step with `starttls: true`.
- `websocket` does not return TLS metrics.

### Certificate revocation

The `probe_ssl_crl_*` metrics appear only when the module sets
`check_revoked: true` and the connection uses TLS.

### HTTP

- `probe_failed_due_to_cel` appears only when the module sets
  `fail_if_body_json_matches_cel` or `fail_if_body_json_not_matches_cel`.
- `probe_http_last_modified_timestamp_seconds` appears only when the response
  has a valid `Last-Modified` header.
- `probe_dns_lookup_time_seconds`, `probe_ip_protocol` and
  `probe_ip_addr_hash` are missing when the module sets
  `skip_resolve_phase_with_proxy: true` and uses a proxy, because the proxy
  resolves the target then.

### DNS

`probe_dns_serial` appears only for SOA queries (`query_type: SOA`).

### ICMP

`probe_icmp_reply_hop_limit` appears only when the exporter can read the hop
limit (TTL for IPv4) of the reply.

### Query and response

`probe_expect_info` appears when a `query_response` step of a `tcp` or `unix`
module has both `expect` and `labels`, and the `expect` regular expression
matches. The label names are the configured `labels[].name` values.

### Label values

The `phase` label of the `probe_*_duration_seconds` metrics takes these values:

| Prober | Phases |
|---|---|
| http | `resolve`, `connect`, `tls`, `processing`, `transfer` |
| dns | `resolve`, `connect`, `request` |
| icmp | `resolve`, `setup`, `rtt` |
| grpc | `resolve`, `check` |
| websocket | `resolve`, `connect`, `processing`, `transfer` |

The `serving_status` label of `probe_grpc_healthcheck_response` takes the
values of the gRPC health checking protocol: `UNKNOWN`, `SERVING`,
`NOT_SERVING` and `SERVICE_UNKNOWN`. If the server returned a status, its
series is 1 and the others are 0.
