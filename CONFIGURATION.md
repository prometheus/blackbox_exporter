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

### Address selection

The blackbox_exporter is a testing tool.  Because of this requirement it
does not behave like a typical end-user client.  Only a single connection
attempt is made to the target under test.  There is no "happy eyeballs"
style of connection parallelization or retry.

When you run a test, you want to know what you're testing.  If a host has
both AAAA and A records then you should be running two separate tests: you
don't want the service being "half up" to be considered as "working".  (Such
issues are the bane of the dual stack world, where nobody notices IPv6 going
down).

Therefore, if the target is specified using a hostname, and that hostname
resolves to multiple addresses (from the same or different address families)
then a single address is selected to test, using the following logic:

* If `ip_protocol_fallback` is `true` (the default), then the connection can
  be made over either IPv4 or IPv6.  If addresses from both families are
  available, then `preferred_ip_protocol` is used.
* If `ip_protocol_fallback` is `false`, then only IPv4 or IPv6 is used, as
  specified by `preferred_ip_protocol`.  The connection will fail if an
  address from the specified family is not available.
* If there are multiple addresses in the chosen address family, then only
  the first one found is used.  In the case of round-robin DNS this
  means that effectively one will be selected at random.

### `<module>`
```yml

  # The protocol over which the probe will take place (http, tcp, dns, icmp, grpc, unix).
  prober: <prober_string>

  # How long the probe will wait before giving up.
  [ timeout: <duration> ]

  # The specific probe configuration - at most one of these should be specified.
  [ http: <http_probe> ]
  [ tcp: <tcp_probe> ]
  [ dns: <dns_probe> ]
  [ icmp: <icmp_probe> ]
  [ grpc: <grpc_probe> ]
  [ unix: <unix_probe> ]
  [ websocket: <websocket_probe> ]

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

  # Additional HTTP headers that can be injected into the request.
  # Can be used with values, secrets or files. When multiple types
  # or values are specified for a header, only the last one will be injected.
  http_headers:
    [ <string>:
      [ values: <string>, ... ],
      [ secrets: <string>, ... ],
      [ files: <string>, ... ]
    ], ...

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

  # Probe fails if response body JSON matches the CEL expression or if response is not JSON. See: https://github.com/google/cel-spec:
  fail_if_body_json_matches_cel: <string>

  # Probe fails if response body JSON does not match CEL expression or if response is not JSON. See: https://github.com/google/cel-spec:
  fail_if_body_json_not_matches_cel: <string>

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

  # Check each certificate in the TLS chain against its CRL and emit probe_ssl_crl_* metrics.
  # This only reports revocation state, it never fails the probe: a revoked certificate or
  # an unreachable CRL leaves probe_success untouched. Alert on the metrics instead.
  # CRLs are fetched using the proxy settings configured below.
  [ check_revoked: <boolean> | default = false ]

  # The HTTP basic authentication credentials.
  basic_auth:
    [ username: <string> ]
    [ password: <secret> ]
    [ username_file: <filename> ]
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

  # Whether to enable HTTP3.
  # Note: When enable_http3 is true, valid_http_versions must not include HTTP/2.0
  # as HTTP/3 and HTTP/2 cannot be used together. Additionally, when enable_http3
  # is true, enable_http2 must be set to false.
  [ enable_http3: <bool> | default: false ]

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
# "expect" matches a regular expression; it is mutually exclusive with "expect_bytes".
# "expect_bytes" does exact byte-by-byte match; it is mutually exclusive with "expect".
# "labels" can define labels which will be exported on metric "probe_expect_info";
# "send" sends some content;
# "send" and "labels.value" can contain values matched by "expect" (such as "${1}");
# "starttls" upgrades TCP connection to TLS.
query_response:
  [ - [ [ expect: <string> ],
        [ expect_bytes: <string> ],
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

# Check each certificate in the TLS chain against its CRL and emit probe_ssl_crl_* metrics.
# This only reports revocation state, it never fails the probe: a revoked certificate or
# an unreachable CRL leaves probe_success untouched. Alert on the metrics instead.
# Requires tls to be true, or a query_response step using starttls.
[ check_revoked: <boolean> | default = false ]

```

### `<unix_probe>`

```yml

# The query sent in the unix socket probe and the expected associated response.
# "expect" matches a regular expression;
# "expect_bytes" does exact byte-by-byte match, mutually exclusive with "expect".
# "labels" can define labels which will be exported on metric "probe_expect_info";
# "send" sends some content;
# "send" and "labels.value" can contain values matched by "expect" (such as "${1}");
# "starttls" upgrades connection to TLS.
query_response:
  [ - [ [ expect: <string> ],
        [ expect_bytes: <string> ],
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

# Configuration for TLS protocol of unix socket probe.
tls_config:
  [ <tls_config> ]

# Check each certificate in the TLS chain against its CRL and emit probe_ssl_crl_* metrics.
# This only reports revocation state, it never fails the probe: a revoked certificate or
# an unreachable CRL leaves probe_success untouched. Alert on the metrics instead.
# Requires tls to be true, or a query_response step using starttls.
[ check_revoked: <boolean> | default = false ]

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

By default the gRPC prober uses the [gRPC Health Checking Protocol](https://github.com/grpc/grpc/blob/master/doc/health-checking.md).
Setting `unary_method` makes it call an arbitrary unary method instead.

```yml
# The service name to query for health status.
# Mutually exclusive with unary_method.
[ service: <string> ]

# The IP protocol of the gRPC probe (ip4, ip6).
[ preferred_ip_protocol: <string> | default = "ip6"]
[ ip_protocol_fallback: <boolean> | default = true ]

# gRPC client metadata
metadata:
  [ <string>: 
    [ - <string> ], ...  
  ], ...

# Whether to connect to the endpoint with TLS.
[ tls: <boolean | default = false> ]

# Configuration for TLS protocol of gRPC probe.
tls_config:
  [ <tls_config> ]

# Check each certificate in the TLS chain against its CRL and emit probe_ssl_crl_* metrics.
# This only reports revocation state, it never fails the probe: a revoked certificate or
# an unreachable CRL leaves probe_success untouched. Alert on the metrics instead.
# Requires tls to be true.
[ check_revoked: <boolean> | default = false ]

# Call an arbitrary unary method instead of the health check.
[ unary_method: <grpc_unary_method> ]
```

#### `<grpc_unary_method>`

The request and response messages are built at probe time from the method's
protobuf descriptors. These are fetched with
[gRPC server reflection](https://grpc.io/docs/guides/reflection/) (v1, falling
back to v1alpha), unless `descriptor_set_file` is set. The `metadata`,
`tls` and `tls_config` settings of the gRPC probe apply to both the reflection
request and the method call, and the call is bound by the module `timeout`.

```yml
# The fully-qualified name of the method to call, e.g.
# "helloworld.Greeter/SayHello". "helloworld.Greeter.SayHello" is also accepted.
method: <string>

# The request message in the protobuf JSON format
# (https://protobuf.dev/programming-guides/json/). Defaults to an empty message.
[ request: <string> ]

# A binary FileDescriptorSet describing the method, as produced by
# `protoc --include_imports --descriptor_set_out=<file>` or `buf build -o <file>`.
# When set, server reflection is not used. Well-known types may be left out.
[ descriptor_set_file: <filename> ]

# The status codes that make the probe succeed, by name (e.g. NOT_FOUND)
# or number. Defaults to OK.
valid_status_codes:
  [ - <string> ... ]

# The response is matched in its protobuf JSON representation, with insignificant
# whitespace removed and fields in lowerCamelCase, e.g.
# {"message":"Hello blackbox"}. Fields with default values are omitted.
# Response matchers are only evaluated when the status code is OK.

# Probe fails if the response matches the regex.
fail_if_response_matches_regexp:
  [ - <regex>, ... ]

# Probe fails if the response does not match the regex.
fail_if_response_not_matches_regexp:
  [ - <regex>, ... ]

# Probe fails if the response matches the CEL expression. The response is
# available as `body`.
[ fail_if_response_json_matches_cel: <string>, ... ]

# Probe fails if the response does not match the CEL expression. The response is
# available as `body`.
[ fail_if_response_json_not_matches_cel: <string>, ... ]
```

When `unary_method` is set, the probe exposes the following metrics in
addition to the common gRPC ones:

* `probe_grpc_duration_seconds{phase="reflection"}`: time spent fetching
  descriptors with server reflection, and `phase="check"`: time spent in the
  method call.
* `probe_grpc_reflection_status_code`: the status code of the server reflection
  request. Only exposed when server reflection is used.
* `probe_grpc_status_code`: the status code returned by the method. Only
  exposed when the method was called.
* `probe_grpc_response_size_bytes`: the size of the protobuf-encoded response
  message, when the status code is OK.
* `probe_failed_due_to_regex` and `probe_failed_due_to_cel`: whether the response
  matchers caused the probe to fail, when they are configured.

### `<websocket_probe>`

```yml
# Optional HTTP request configuration
http_config:
  [ <http_client_config> ]

# The HTTP headers set for the probe.
# The HTTP headers set for the probe.
headers:
  [ <string>:
    [ values: [<string>, ...] ],
    [ secrets: [<secret>, ...] ],
    [ files: [<filename>, ...] ]
  ], ...

# The query sent after connection upgrade and the expected associated response.
# "expect" matches a regular expression against incoming messages;
# "send" sends a message (can use values matched by "expect" such as "${1}").
query_response:
  [ - [ expect: <regex> ],
        [ send: <string> ],
        [ starttls: <boolean | default = false> ]
      ], ...
  ]

  # The IP protocol of the Websocket probe (ip4, ip6).
  [ preferred_ip_protocol: <string> | default = "ip6" ]

  # Fallback to the other IP protocol if the `preferred_ip_protocol` fails.
  [ ip_protocol_fallback: <boolean> | default = true ]

```

### `<http_client_config>`

```yml
  # The HTTP basic authentication credentials.
  basic_auth:
    [ username: <string> ]
    [ password: <secret> ]
    [ username_file: <filename> ]
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

  # OAuth 2.0 configuration to use to connect to the targets.
  oauth2:
    [ <oauth2> ]

  # Whether to enable HTTP2.
  [ enable_http2: <bool> | default: true ]

  # Configuration for TLS protocol of HTTP probe.
  tls_config:
    [ <tls_config> ]

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

  # Whether or not the probe will follow any redirects.
  [ follow_redirects: <boolean> | default = true ]
```

### `<tls_config>`

```yml

# Disable target certificate validation.
[ insecure_skip_verify: <boolean> | default = false ]

# The CA cert to use for the targets.
[ ca_file: <filename> ]

# Text of the CA cert to use for the targets.
# It is mutually exclusive with `ca_file`.
[ ca: <string> ]

# The client cert file for the targets.
[ cert_file: <filename> ]

# Text of the client cert for the targets.
# It is mutually exclusive with `cert_file`.
[ cert: <string> ]

# The client key file for the targets.
[ key_file: <filename> ]

# Text of the client key for the targets.
# It is mutually exclusive with `key_file`.
[ key: <secret> ]

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

OAuth 2.0 authentication using the client credentials grant type, or the JWT
bearer grant type (RFC 7523). Blackbox exporter fetches an access token from
the specified endpoint with the given client access and secret keys, or with a
JWT signed by the given private key.

NOTE: This is *experimental* in the blackbox exporter and might not be
reflected properly in the probe metrics at the moment.

```yml
client_id: <string>

# The OAuth2 grant type. One of `client_credentials` or
# `urn:ietf:params:oauth:grant-type:jwt-bearer`.
[ grant_type: <string> | default = "client_credentials" ]

# Used with the `client_credentials` grant type.
[ client_secret: <secret> ]

# Read the client secret from a file.
# It is mutually exclusive with `client_secret`.
[ client_secret_file: <filename> ]

# Used with the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant type.
# The PEM-encoded RSA private key used to sign the JWT assertion.
[ client_certificate_key: <secret> ]

# Read the private key from a file.
# It is mutually exclusive with `client_certificate_key`.
[ client_certificate_key_file: <filename> ]

# Optional key ID, sent as the `kid` header of the JWT.
[ client_certificate_key_id: <string> ]

# The algorithm used to sign the JWT. One of RS256, RS384 or RS512.
[ signature_algorithm: <string> | default = "RS256" ]

# The `iss` claim of the JWT. Defaults to `client_id`.
[ iss: <string> ]

# The `aud` claim of the JWT. Defaults to `token_url`.
[ audience: <string> ]

# Extra claims added to the JWT.
claims:
  [ <string>: <value> ... ]

# Scopes for the token request.
scopes:
  [ - <string> ... ]

# The URL to fetch the token from.
token_url: <string>

# Optional parameters to append to the token URL.
endpoint_params:
  [ <string>: <string> ... ]

# Configures the token request's TLS settings, for example a client
# certificate for IdPs that authenticate the client with mutual TLS.
tls_config:
  [ <tls_config> ]
```
