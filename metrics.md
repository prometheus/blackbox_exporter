# Blackbox Exporter Metric Documentation

*Those tables are automatically extracted from source code. Do not modify
manually!*


## Dns metrics

| metric name              | doc                                                             |
|--------------------------|-----------------------------------------------------------------|
| probe_dns_additional_rrs | Returns number of entries in the additional resource record list|
| probe_dns_answer_rrs     | Returns number of entries in the answer resource record list    |
| probe_dns_authority_rrs  | Returns number of entries in the authority resource record list |
| probe_dns_serial         | Returns the serial number of the zone                           |

## General metrics

| metric name                                  | doc                                                                               |
|----------------------------------------------|-----------------------------------------------------------------------------------|
| config_last_reload_successful                | Blackbox exporter config loaded successfully.                                     |
| config_last_reload_success_timestamp_seconds | Timestamp of the last successful configuration reload.                            |
| probe_dns_lookup_time_seconds                | Returns the time taken for probe dns lookup in seconds                            |
| probe_duration_seconds                       | Returns how long the probe took to complete in seconds                            |
| probe_ip_addr_hash                           | Specifies the hash of IP address. It's useful to detect if the IP address changes.|
| probe_ip_protocol                            | Specifies whether probe ip protocol is IP4 or IP6                                 |
| probe_success                                | Displays whether or not the probe was a success                                   |

## Http metrics

| metric name                                   | doc                                                         |
|-----------------------------------------------|-------------------------------------------------------------|
| probe_failed_due_to_regex                     | Indicates if probe failed due to regex                      |
| probe_http_content_length                     | Length of http content response                             |
| probe_http_duration_seconds                   | Duration of http request by phase, summed over all redirects|
| probe_http_last_modified_timestamp_seconds    | Returns the Last-Modified HTTP response header in unixtime  |
| probe_http_redirects                          | The number of redirects                                     |
| probe_http_ssl                                | Indicates if SSL was used for the final redirect            |
| probe_http_status_code                        | Response HTTP status code                                   |
| probe_http_uncompressed_body_length           | Length of uncompressed response body                        |
| probe_http_version                            | Returns the version of HTTP of the probe response           |
| probe_ssl_earliest_cert_expiry                | Returns earliest SSL cert expiry in unixtime                |
| probe_ssl_last_chain_expiry_timestamp_seconds | Returns last SSL chain expiry in timestamp seconds          |
| probe_tls_version_info                        | Contains the TLS version used                               |

## Icmp metrics

| metric name                 | doc                                              |
|-----------------------------|--------------------------------------------------|
| probe_icmp_duration_seconds | Duration of icmp request by phase                |

## Tcp metrics

| metric name                                   | doc                                              |
|-----------------------------------------------|--------------------------------------------------|
| probe_failed_due_to_regex                     | Indicates if probe failed due to regex           |
| probe_ssl_earliest_cert_expiry                | Returns earliest SSL cert expiry date            |
| probe_ssl_last_chain_expiry_timestamp_seconds | Returns last SSL chain expiry in unixtime        |
| probe_tls_version_info                        | Returns the TLS version used, or NaN when unknown|
