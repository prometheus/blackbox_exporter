# Blackbox exporter configuration

The file is written in [YAML format](http://en.wikipedia.org/wiki/YAML), defined by the scheme described below.
Brackets indicate that a parameter is optional.
For non-list parameters the value is set to the specified default.

Generic placeholders are defined as follows:

* `<boolean>`: a boolean that can take the values `true` or `false`
* `<int>`: a regular integer
* `<duration>`: a duration matching the regular expression `[0-9]+(ms|[smhdwy])`
* `<filename>`: a valid path in the current working directory
* `<string>`: a regular string
* `<secret>`: a regular string that is a secret, such as a password
* `<regex>`: a regular expression

The other placeholders are specified separately.

See [example.yml](example.yml) for configuration examples.

```yml

modules:
     [ <string>: <module> ... ]

```


### `<module>`
```yml

  # The protocol over which the probe will take place (http, tcp, dns, icmp, grpc).
  prober: <prober_string>

  # How long the probe will wait before giving up.
  [ timeout: <duration> ]

  # The specific probe configuration - at most one of these should be specified.
  [ http: <http_probe> ]
  [ tcp: <tcp_probe> ]
  [ dns: <dns_probe> ]
  [ icmp: <icmp_probe> ]
  [ grpc: <grpc_probe> ]

```

### `<http_probe>`
```yml

  # Accepted status codes for this probe. List between square brackets. Defaults to 2xx.
  [ valid_status_codes: [<int>, ...] | default = 2xx ]

  # Accepted HTTP versions for this probe.
  [ valid_http_versions: <string>, ... ]

  # The HTTP method the probe will use.
  [ method: <string> | default = "GET" ]

  # The HTTP headers set for the probe.
  headers:
    [ <string>: <string> ... ]

  # The maximum uncompressed body length in bytes that will be processed. A value of 0 means no limit.
  #
  # If the response includes a Content-Length header, it is NOT validated against this value. This
  # setting is only meant to limit the amount of data that you are willing to read from the server.
  #
  # Example: 10MB
  [ body_size_limit: <size> | default = 0 ]

  # The compression algorithm to use to decompress the response (gzip, br, deflate, identity).
  #
  # If an "Accept-Encoding" header is specified, it MUST be such that the compression algorithm
  # indicated using this option is acceptable. For example, you can use `compression: gzip` and
  # `Accept-Encoding: br, gzip` or `Accept-Encoding: br;q=1.0, gzip;q=0.9`. The fact that gzip is
  # acceptable with a lower quality than br does not invalidate the configuration, as you might
  # be testing that the server does not return br-encoded content even if it's requested. On the
  # other hand, `compression: gzip` and `Accept-Encoding: br, identity` is NOT a valid
  # configuration, because you are asking for gzip to NOT be returned, and trying to decompress
  # whatever the server returns is likely going to fail.
  [ compression: <string> | default = "" ]

  # Whether or not the probe will follow any redirects.
  [ follow_redirects: <boolean> | default = true ]

  # Probe fails if SSL is present.
  [ fail_if_ssl: <boolean> | default = false ]

  # Probe fails if SSL is not present.
  [ fail_if_not_ssl: <boolean> | default = false ]

  # Probe fails if response body JSON matches CEL:
  fail_if_body_json_matches_cel: <cel expression, root field is called body>

  # Probe fails if response body JSON does not match CEL:
  fail_if_body_json_not_matches_cel: <cel expression, root field is called body>

  # Probe fails if response body matches regex.
  fail_if_body_matches_regexp:
    [ - <regex>, ... ]

  # Probe fails if response body does not match regex.
  fail_if_body_not_matches_regexp:
    [ - <regex>, ... ]

  # Probe fails if response header matches regex. For headers with multiple values, fails if *at least one* matches.
  fail_if_header_matches:
    [ - <http_header_match_spec>, ... ]

  # Probe fails if response header does not match regex. For headers with multiple values, fails if *none* match.
  fail_if_header_not_matches:
    [ - <http_header_match_spec>, ... ]

  # Configuration for TLS protocol of HTTP probe.
  tls_config:
    [ <tls_config> ]

  # The HTTP basic authentication credentials.
  basic_auth:
    [ username: <string> ]
    [ password: <secret> ]
    [ password_file: <filename> ]

  # Sets the `Authorization` header on every request with
  # the configured credentials.
  authorization:
    # Sets the authentication type of the request.
    [ type: <string> | default: Bearer ]
    # Sets the credentials of the request. It is mutually exclusive with
    # `credentials_file`.
    [ credentials: <secret> ]
    # Sets the credentials of the request with the credentials read from the
    # configured file. It is mutually exclusive with `credentials`.
    [ credentials_file: <filename> ]

  # HTTP proxy server to use to connect to the targets.
  [ proxy_url: <string> ]
  # Comma-separated string that can contain IPs, CIDR notation, domain names
  # that should be excluded from proxying. IP and domain names can
  # contain port numbers.
  [ no_proxy: <string> ]
  # Use proxy URL indicated by environment variables (HTTP_PROXY, https_proxy, HTTPs_PROXY, https_proxy, and no_proxy)
  [ proxy_from_environment: <bool> | default: false ]
  # Specifies headers to send to proxies during CONNECT requests.
  [ proxy_connect_header:
    [ <string>: [<secret>, ...] ] ]

  # Skip DNS resolution and URL change when an HTTP proxy (proxy_url or proxy_from_environment) is set.
  [ skip_resolve_phase_with_proxy: <boolean> | default = false ]

  # OAuth 2.0 configuration to use to connect to the targets.
  oauth2:
      [ <oauth2> ]

  # Whether to enable HTTP2.
  [ enable_http2: <bool> | default: true ]

  # The IP protocol of the HTTP probe (ip4, ip6).
  [ preferred_ip_protocol: <string> | default = "ip6" ]
  [ ip_protocol_fallback: <boolean> | default = true ]

  # The body of the HTTP request used in probe.
  [ body: <string> ]

  # Read the HTTP request body from from a file.
  # It is mutually exclusive with `body`.
  [ body_file: <filename> ]

```

#### `<http_header_match_spec>`

```yml
header: <string>,
regexp: <regex>,
[ allow_missing: <boolean> | default = false ]
```

### `<tcp_probe>`

```yml

# The IP protocol of the TCP probe (ip4, ip6).
[ preferred_ip_protocol: <string> | default = "ip6" ]
[ ip_protocol_fallback: <boolean | default = true> ]

# The source IP address.
[ source_ip_address: <string> ]

# The query sent in the TCP probe and the expected associated response.
# "expect" matches a regular expression;
# "labels" can define labels which will be exported on metric "probe_expect_info";
# "send" sends some content;
# "send" and "labels.value" can contain values matched by "expect" (such as "${1}");
# "starttls" upgrades TCP connection to TLS.
query_response:
  [ - [ [ expect: <string> ],
        [ labels:
          - [ name: <string>
              value: <string>
            ], ...
        ],
        [ send: <string> ],
        [ starttls: <boolean | default = false> ]
      ], ...
  ]

# Whether or not TLS is used when the connection is initiated.
[ tls: <boolean | default = false> ]

# Configuration for TLS protocol of TCP probe.
tls_config:
  [ <tls_config> ]

```

### `<dns_probe>`

```yml

# The IP protocol of the DNS probe (ip4, ip6).
[ preferred_ip_protocol: <string> | default = "ip6" ]
[ ip_protocol_fallback: <boolean | default = true> ]

# The source IP address.
[ source_ip_address: <string> ]

[ transport_protocol: <string> | default = "udp" ] # udp, tcp

# Whether to use DNS over TLS. This only works with TCP.
[ dns_over_tls: <boolean | default = false> ]

# Configuration for TLS protocol of DNS over TLS probe.
tls_config:
  [ <tls_config> ]

query_name: <string>

[ query_type: <string> | default = "ANY" ]
[ query_class: <string> | default = "IN" ]

# Set the recursion desired (RD) flag in the request.
[ recursion_desired: <boolean> | default = true ]

# List of valid response codes.
valid_rcodes:
  [ - <string> ... | default = "NOERROR" ]

validate_answer_rrs:

  fail_if_matches_regexp:
    [ - <regex>, ... ]

  fail_if_all_match_regexp:
    [ - <regex>, ... ]

  fail_if_not_matches_regexp:
    [ - <regex>, ... ]

  fail_if_none_matches_regexp:
    [ - <regex>, ... ]

validate_authority_rrs:

  fail_if_matches_regexp:
    [ - <regex>, ... ]

  fail_if_all_match_regexp:
    [ - <regex>, ... ]

  fail_if_not_matches_regexp:
    [ - <regex>, ... ]

  fail_if_none_matches_regexp:
    [ - <regex>, ... ]

validate_additional_rrs:

  fail_if_matches_regexp:
    [ - <regex>, ... ]

  fail_if_all_match_regexp:
    [ - <regex>, ... ]

  fail_if_not_matches_regexp:
    [ - <regex>, ... ]

  fail_if_none_matches_regexp:
    [ - <regex>, ... ]

```

### `<icmp_probe>`

```yml

# The IP protocol of the ICMP probe (ip4, ip6).
[ preferred_ip_protocol: <string> | default = "ip6" ]
[ ip_protocol_fallback: <boolean | default = true> ]

# The source IP address.
[ source_ip_address: <string> ]

# Set the DF-bit in the IP-header. Only works with ip4, on *nix systems and
# requires raw sockets (i.e. root or CAP_NET_RAW on Linux).
[ dont_fragment: <boolean> | default = false ]

# The size of the payload.
[ payload_size: <int> ]

# TTL of outbound packets. Value must be in the range [0, 255]. Can be used
# to test reachability of a target within a given number of hops, for example,
# to determine when network routing has changed.
[ ttl: <int> ]

```

### `<grpc_probe>`

```yml
# The service name to query for health status.
[ service: <string> ]

# The IP protocol of the gRPC probe (ip4, ip6).
[ preferred_ip_protocol: <string> ]
[ ip_protocol_fallback: <boolean> | default = true ]

# Whether to connect to the endpoint with TLS.
[ tls: <boolean | default = false> ]

# Configuration for TLS protocol of gRPC probe.
tls_config:
  [ <tls_config> ]
```

### `<tls_config>`

```yml

# Disable target certificate validation.
[ insecure_skip_verify: <boolean> | default = false ]

# The CA cert to use for the targets.
[ ca_file: <filename> ]

# The client cert file for the targets.
[ cert_file: <filename> ]

# The client key file for the targets.
[ key_file: <filename> ]

# Used to verify the hostname for the targets.
[ server_name: <string> ]

# Minimum acceptable TLS version. Accepted values: TLS10 (TLS 1.0), TLS11 (TLS
# 1.1), TLS12 (TLS 1.2), TLS13 (TLS 1.3).
# If unset, Prometheus will use Go default minimum version, which is TLS 1.2.
# See MinVersion in https://pkg.go.dev/crypto/tls#Config.
[ min_version: <string> ]

# Maximum acceptable TLS version. Accepted values: TLS10 (TLS 1.0), TLS11 (TLS
# 1.1), TLS12 (TLS 1.2), TLS13 (TLS 1.3).
# Can be used to test for the presence of insecure TLS versions.
# If unset, Prometheus will use Go default maximum version, which is TLS 1.3.
# See MaxVersion in https://pkg.go.dev/crypto/tls#Config.
[ max_version: <string> ]
```

#### `<oauth2>`

OAuth 2.0 authentication using the client credentials grant type. Blackbox
exporter fetches an access token from the specified endpoint with the given
client access and secret keys.

NOTE: This is *experimental* in the blackbox exporter and might not be
reflected properly in the probe metrics at the moment.

```yml
client_id: <string>
[ client_secret: <secret> ]

# Read the client secret from a file.
# It is mutually exclusive with `client_secret`.
[ client_secret_file: <filename> ]

# Scopes for the token request.
scopes:
  [ - <string> ... ]

# The URL to fetch the token from.
token_url: <string>

# Optional parameters to append to the token URL.
endpoint_params:
  [ <string>: <string> ... ]
```
