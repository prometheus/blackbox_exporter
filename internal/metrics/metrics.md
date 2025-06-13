# Metrics


## blackbox

### blackbox_module_unknown_total
Count of unknown modules requested by probes

```promql
# TYPE blackbox_module_unknown_total COUNTER
blackbox_module_unknown_total{}
```





## config

### blackbox_exporter_config_last_reload_success_timestamp_seconds
Timestamp of the last successful configuration reload

```promql
# TYPE blackbox_exporter_config_last_reload_success_timestamp_seconds GAUGE
blackbox_exporter_config_last_reload_success_timestamp_seconds{}
```




### blackbox_exporter_config_last_reload_successful
Blackbox exporter config loaded successfully

```promql
# TYPE blackbox_exporter_config_last_reload_successful GAUGE
blackbox_exporter_config_last_reload_successful{}
```





## dns

### probe_dns_additional_rrs
Returns number of entries in the additional resource record list

```promql
# TYPE probe_dns_additional_rrs GAUGE
probe_dns_additional_rrs{}
```




### probe_dns_answer_rrs
Returns number of entries in the answer resource record list

```promql
# TYPE probe_dns_answer_rrs GAUGE
probe_dns_answer_rrs{}
```




### probe_dns_authority_rrs
Returns number of entries in the authority resource record list

```promql
# TYPE probe_dns_authority_rrs GAUGE
probe_dns_authority_rrs{}
```




### probe_dns_duration_seconds
Duration of DNS request by phase

```promql
# TYPE probe_dns_duration_seconds GAUGE
probe_dns_duration_seconds{phase}
```


|Attribute|Type|Description|
|-|-|-|
| phase | `resolve` \| `connect` \| `request` \| `tls` \| `processing` \| `transfer` \| `setup` \| `rtt` \| `check` | Probe phase  |




### probe_dns_query_succeeded
Displays whether or not the query was executed successfully

```promql
# TYPE probe_dns_query_succeeded GAUGE
probe_dns_query_succeeded{}
```




### probe_dns_serial
Returns the serial number of the zone

```promql
# TYPE probe_dns_serial GAUGE
probe_dns_serial{}
```





## grpc

### probe_grpc_duration_seconds
Duration of gRPC request by phase

```promql
# TYPE probe_grpc_duration_seconds GAUGE
probe_grpc_duration_seconds{phase}
```


|Attribute|Type|Description|
|-|-|-|
| phase | `resolve` \| `connect` \| `request` \| `tls` \| `processing` \| `transfer` \| `setup` \| `rtt` \| `check` | Probe phase  |




### probe_grpc_healthcheck_response
Response HealthCheck response

```promql
# TYPE probe_grpc_healthcheck_response GAUGE
probe_grpc_healthcheck_response{serving_status}
```


|Attribute|Type|Description|
|-|-|-|
| serving_status | `SERVING` \| `NOT_SERVING` \| `UNKNOWN` \| `SERVICE_UNKNOWN` | gRPC health check serving status  |




### probe_grpc_ssl
Indicates if SSL was used for the connection

```promql
# TYPE probe_grpc_ssl GAUGE
probe_grpc_ssl{}
```




### probe_grpc_status_code
Response gRPC status code

```promql
# TYPE probe_grpc_status_code GAUGE
probe_grpc_status_code{}
```





## http

### probe_failed_due_to_cel
Indicates if probe failed due to CEL expression not matching

```promql
# TYPE probe_failed_due_to_cel GAUGE
probe_failed_due_to_cel{}
```




### probe_http_content_length
Length of http content response

```promql
# TYPE probe_http_content_length GAUGE
probe_http_content_length{}
```




### probe_http_duration_seconds
Duration of http request by phase, summed over all redirects

```promql
# TYPE probe_http_duration_seconds GAUGE
probe_http_duration_seconds{phase}
```


|Attribute|Type|Description|
|-|-|-|
| phase | `resolve` \| `connect` \| `request` \| `tls` \| `processing` \| `transfer` \| `setup` \| `rtt` \| `check` | Probe phase  |




### probe_http_last_modified_timestamp_seconds
Returns the Last-Modified HTTP response header in unixtime

```promql
# TYPE probe_http_last_modified_timestamp_seconds GAUGE
probe_http_last_modified_timestamp_seconds{}
```




### probe_http_redirects
The number of redirects

```promql
# TYPE probe_http_redirects GAUGE
probe_http_redirects{}
```




### probe_http_ssl
Indicates if SSL was used for the final redirect

```promql
# TYPE probe_http_ssl GAUGE
probe_http_ssl{}
```




### probe_http_status_code
Response HTTP status code

```promql
# TYPE probe_http_status_code GAUGE
probe_http_status_code{}
```




### probe_http_uncompressed_body_length
Length of uncompressed response body

```promql
# TYPE probe_http_uncompressed_body_length GAUGE
probe_http_uncompressed_body_length{}
```




### probe_http_version
Returns the version of HTTP of the probe response

```promql
# TYPE probe_http_version GAUGE
probe_http_version{}
```





## icmp

### probe_icmp_duration_seconds
Duration of icmp request by phase

```promql
# TYPE probe_icmp_duration_seconds GAUGE
probe_icmp_duration_seconds{phase}
```


|Attribute|Type|Description|
|-|-|-|
| phase | `resolve` \| `connect` \| `request` \| `tls` \| `processing` \| `transfer` \| `setup` \| `rtt` \| `check` | Probe phase  |




### probe_icmp_reply_hop_limit
Replied packet hop limit (TTL for ipv4)

```promql
# TYPE probe_icmp_reply_hop_limit GAUGE
probe_icmp_reply_hop_limit{}
```





## probe

### probe_dns_lookup_time_seconds
Returns the time taken for probe dns lookup in seconds

```promql
# TYPE probe_dns_lookup_time_seconds GAUGE
probe_dns_lookup_time_seconds{}
```




### probe_duration_seconds
Returns how long the probe took to complete in seconds

```promql
# TYPE probe_duration_seconds GAUGE
probe_duration_seconds{}
```




### probe_failed_due_to_regex
Indicates if probe failed due to regex

```promql
# TYPE probe_failed_due_to_regex GAUGE
probe_failed_due_to_regex{}
```




### probe_ip_addr_hash
Specifies the hash of IP address. It's useful to detect if the IP address changes.

```promql
# TYPE probe_ip_addr_hash GAUGE
probe_ip_addr_hash{}
```




### probe_ip_protocol
Specifies whether probe ip protocol is IP4 or IP6

```promql
# TYPE probe_ip_protocol GAUGE
probe_ip_protocol{}
```




### probe_success
Displays whether or not the probe was a success

```promql
# TYPE probe_success GAUGE
probe_success{}
```





## ssl

### probe_ssl_earliest_cert_expiry
Returns earliest SSL cert expiry date

```promql
# TYPE probe_ssl_earliest_cert_expiry GAUGE
probe_ssl_earliest_cert_expiry{}
```




### probe_ssl_last_chain_expiry_timestamp_seconds
Returns last SSL chain expiry timestamp

```promql
# TYPE probe_ssl_last_chain_expiry_timestamp_seconds GAUGE
probe_ssl_last_chain_expiry_timestamp_seconds{}
```




### probe_ssl_last_chain_info
Contains SSL leaf certificate information

```promql
# TYPE probe_ssl_last_chain_info GAUGE
probe_ssl_last_chain_info{fingerprint_sha256, subject, issuer, subjectalternative, serialnumber}
```


|Attribute|Type|Description|
|-|-|-|
| fingerprint_sha256 | string | SHA256 fingerprint of the certificate  |
| subject | string | Subject of the certificate  |
| issuer | string | Issuer of the certificate  |
| subjectalternative | string | Subject alternative names of the certificate  |
| serialnumber | string | Serial number of the certificate  |





## tcp

### probe_expect_info
Explicit content matched

```promql
# TYPE probe_expect_info GAUGE
probe_expect_info{}
```





## tls

### probe_tls_cipher_info
Contains TLS cipher information

```promql
# TYPE probe_tls_cipher_info GAUGE
probe_tls_cipher_info{cipher}
```


|Attribute|Type|Description|
|-|-|-|
| cipher | string | TLS cipher suite  |




### probe_tls_version_info
Contains TLS version information

```promql
# TYPE probe_tls_version_info GAUGE
probe_tls_version_info{version}
```


|Attribute|Type|Description|
|-|-|-|
| version | string | TLS version  |




