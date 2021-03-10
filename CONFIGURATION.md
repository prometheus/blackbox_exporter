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

### Module
```yml

  # The protocol over which the probe will take place (http, tcp, dns, icmp).
  prober: <prober_string>

  # How long the probe will wait before giving up.
  [ timeout: <duration> ]

  # The specific probe configuration - at most one of these should be specified.
  [ http: <http_probe> ]
  [ tcp: <tcp_probe> ]
  [ dns: <dns_probe> ]
  [ icmp: <icmp_probe> ]

```

### <http_probe>
```yml

  # Accepted status codes for this probe. Defaults to 2xx.
  [ valid_status_codes: <int>, ... | default = 2xx ]

  # Accepted HTTP versions for this probe.
  [ valid_http_versions: <string>, ... ]

  # The HTTP method the probe will use.
  [ method: <string> | default = "GET" ]

  # The HTTP headers set for the probe.
  headers:
    [ <string>: <string> ... ]

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
  [ no_follow_redirects: <boolean> | default = false ]

  # Probe fails if SSL is present.
  [ fail_if_ssl: <boolean> | default = false ]

  # Probe fails if SSL is not present.
  [ fail_if_not_ssl: <boolean> | default = false ]

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

  # The HTTP basic authentication credentials for the targets.
  basic_auth:
    [ username: <string> ]
    [ password: <secret> ]
    [ password_file: <filename> ]

  # The bearer token for the targets.
  [ bearer_token: <secret> ]

  # The bearer token file for the targets.
  [ bearer_token_file: <filename> ]

  # HTTP proxy server to use to connect to the targets.
  [ proxy_url: <string> ]

  # The IP protocol of the HTTP probe (ip4, ip6).
  [ preferred_ip_protocol: <string> | default = "ip6" ]
  [ ip_protocol_fallback: <boolean> | default = true ]

  # The body of the HTTP request used in probe.
  body: [ <string> ]


```

#### <http_header_match_spec>

```yml
header: <string>,
regexp: <regex>,
[ allow_missing: <boolean> | default = false ]
```

### <tcp_probe>

```yml

# The IP protocol of the TCP probe (ip4, ip6).
[ preferred_ip_protocol: <string> | default = "ip6" ]
[ ip_protocol_fallback: <boolean | default = true> ]

# The source IP address.
[ source_ip_address: <string> ]

# The query sent in the TCP probe and the expected associated response.
# starttls upgrades TCP connection to TLS.
query_response:
  [ - [ [ expect: <string> ],
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

### <dns_probe>

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

### <icmp_probe>

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

```

### <tls_config>

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

```
